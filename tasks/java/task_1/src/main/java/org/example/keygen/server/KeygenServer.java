package org.example.keygen.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.example.keygen.common.KeyCertPair;
import org.example.keygen.crypto.CryptoService;

/**
 * Высокопроизводительный сервер генерации ключей на базе Java NIO Selector
 * и фиксированного пула криптографических потоков.
 */
public class KeygenServer implements AutoCloseable {

    public record OutboundTask(ClientSession session, KeyCertPair pair, Throwable error) {}

    private final ServerConfig config;
    private final CryptoService cryptoService;

    private final ConcurrentHashMap<String, CompletableFuture<KeyCertPair>> cache = new ConcurrentHashMap<>();
    private final ConcurrentLinkedQueue<OutboundTask> outboundQueue = new ConcurrentLinkedQueue<>();

    private Selector selector;
    private ServerSocketChannel serverChannel;
    private ExecutorService workerPool;
    private Thread reactorThread;
    private volatile boolean running = false;
    private final ByteBuffer readBuffer = ByteBuffer.allocate(1024);

    private final AtomicInteger activeConnections = new AtomicInteger(0);

    public KeygenServer(ServerConfig config, CryptoService cryptoService) {
        this.config = Objects.requireNonNull(config, "config cannot be null");
        this.cryptoService = Objects.requireNonNull(cryptoService, "cryptoService cannot be null");
    }

    /**
     * Запускает сервер: открывает сокет, стартует пул потоков и поток NIO Reactor.
     *
     * @throws IOException при ошибках привязки сетевого сокета
     */
    public synchronized void start() throws IOException {
        if (running) {
            return;
        }

        this.selector = Selector.open();
        this.serverChannel = ServerSocketChannel.open();
        this.serverChannel.configureBlocking(false);
        this.serverChannel.bind(new InetSocketAddress(config.host(), config.port()));
        this.serverChannel.register(selector, SelectionKey.OP_ACCEPT);

        AtomicInteger workerIndex = new AtomicInteger(1);
        this.workerPool = Executors.newFixedThreadPool(config.threads(), r -> {
            Thread t = new Thread(r, "crypto-worker-" + workerIndex.getAndIncrement());
            t.setDaemon(true);
            return t;
        });

        this.running = true;
        this.reactorThread = new Thread(this::runReactorLoop, "nio-reactor");
        this.reactorThread.start();

        System.out.printf("Сервер успешно запущен на %s:%d (потоков генерации: %d, размер ключа: %d бит)%n",
                config.host(), getPort(), config.threads(), config.keySize());
    }

    /**
     * Возвращает фактический порт, на котором слушает сервер (удобно при port = 0).
     */
    public int getPort() {
        if (serverChannel != null && serverChannel.isOpen()) {
            try {
                return ((InetSocketAddress) serverChannel.getLocalAddress()).getPort();
            } catch (IOException ignored) {
            }
        }
        return config.port();
    }

    private void runReactorLoop() {
        while (running && selector.isOpen()) {
            try {
                processOutboundQueue();

                int readyChannels = selector.select(100);
                if (!running) {
                    break;
                }

                processOutboundQueue();

                if (readyChannels == 0) {
                    continue;
                }

                Set<SelectionKey> selectedKeys = selector.selectedKeys();
                Iterator<SelectionKey> iterator = selectedKeys.iterator();

                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();

                    if (!key.isValid()) {
                        continue;
                    }

                    try {
                        if (key.isAcceptable()) {
                            handleAccept(key);
                        } else if (key.isReadable()) {
                            handleRead(key);
                        } else if (key.isWritable()) {
                            handleWrite(key);
                        }
                    } catch (Exception e) {
                        closeSessionSilently(key);
                    }
                }
            } catch (Exception e) {
                if (running) {
                    System.err.println("Ошибка в цикле Reactor: " + e.getMessage());
                }
            }
        }
    }

    private void handleAccept(SelectionKey key) throws IOException {
        ServerSocketChannel server = (ServerSocketChannel) key.channel();
        SocketChannel client = server.accept();
        if (client != null) {
            client.configureBlocking(false);
            client.setOption(StandardSocketOptions.TCP_NODELAY, true);
            ClientSession session = new ClientSession(client);
            SelectionKey clientKey = client.register(selector, SelectionKey.OP_READ, session);
            session.setSelectionKey(clientKey);
            activeConnections.incrementAndGet();
        }
    }

    private void handleRead(SelectionKey key) throws IOException {
        ClientSession session = (ClientSession) key.attachment();
        SocketChannel channel = session.getChannel();

        readBuffer.clear();
        int bytesRead = channel.read(readBuffer);

        if (bytesRead == -1) {
            // Клиент закрыл соединение
            closeSessionSilently(key);
            return;
        }

        readBuffer.flip();
        try {
            boolean nameFinished = session.readNameBytes(readBuffer);
            if (nameFinished) {
                // Имя прочитано — снимаем интерес к чтению, чтобы не вызывать select зря
                key.interestOps(0);
                submitGeneration(session, session.getClientName());
            }
        } catch (IllegalArgumentException e) {
            // Превышение лимита длины имени
            System.err.println("Отклонение клиента: " + e.getMessage());
            closeSessionSilently(key);
        }
    }

    private void handleWrite(SelectionKey key) {
        ClientSession session = (ClientSession) key.attachment();
        try {
            boolean finished = session.flush();
            if (finished) {
                key.cancel();
                session.close();
                activeConnections.decrementAndGet();
            }
        } catch (IOException e) {
            closeSessionSilently(key);
        }
    }

    /**
     * Передает запрос на генерацию ключа в пул или использует кэш.
     */
    private void submitGeneration(ClientSession session, String name) {
        CompletableFuture<KeyCertPair> future = cache.computeIfAbsent(name, keyName -> {
            CompletableFuture<KeyCertPair> f = new CompletableFuture<>();
            workerPool.submit(() -> {
                try {
                    KeyCertPair pair = cryptoService.generate(keyName);
                    f.complete(pair);
                } catch (Throwable t) {
                    f.completeExceptionally(t);
                }
            });
            return f;
        });

        // Подписываем сессию на завершение (сработает сразу, если ключ уже был в кэше)
        future.whenComplete((pair, error) -> {
            outboundQueue.add(new OutboundTask(session, pair, error));
            if (selector != null && selector.isOpen()) {
                selector.wakeup();
            }
        });
    }

    /**
     * Обрабатывает очередь отправки готовых результатов клиентам.
     */
    private void processOutboundQueue() {
        OutboundTask task;
        while ((task = outboundQueue.poll()) != null) {
            ClientSession session = task.session();
            if (session.getState() == ClientSession.State.CLOSED || !session.getChannel().isOpen()) {
                continue;
            }

            if (task.error() != null) {
                System.err.println("Ошибка генерации ключа для клиента " + session.getClientName() + ": " + task.error().getMessage());
                session.close();
                activeConnections.decrementAndGet();
                continue;
            }

            session.prepareOutboundPayload(task.pair().toWirePayload());
            try {
                boolean completed = session.flush();
                if (completed) {
                    session.close();
                    activeConnections.decrementAndGet();
                } else {
                    // Буфер сокета полон (медленный клиент) — регистрируем OP_WRITE
                    SelectionKey key = session.getSelectionKey();
                    if (key != null && key.isValid()) {
                        key.interestOps(SelectionKey.OP_WRITE);
                    }
                }
            } catch (IOException e) {
                session.close();
                activeConnections.decrementAndGet();
            }
        }
    }

    private void closeSessionSilently(SelectionKey key) {
        if (key != null) {
            key.cancel();
            Object attachment = key.attachment();
            if (attachment instanceof ClientSession session) {
                session.close();
                activeConnections.decrementAndGet();
            }
        }
    }

    public int getActiveConnectionsCount() {
        return Math.max(0, activeConnections.get());
    }

    public int getCachedKeysCount() {
        return cache.size();
    }

    @Override
    public synchronized void close() {
        running = false;
        if (selector != null && selector.isOpen()) {
            selector.wakeup();
        }

        if (workerPool != null) {
            workerPool.shutdownNow();
            try {
                workerPool.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
            }
        }

        if (serverChannel != null && serverChannel.isOpen()) {
            try {
                serverChannel.close();
            } catch (IOException ignored) {
            }
        }

        if (selector != null && selector.isOpen()) {
            try {
                selector.close();
            } catch (IOException ignored) {
            }
        }

        if (reactorThread != null) {
            try {
                reactorThread.join(2000);
            } catch (InterruptedException ignored) {
            }
        }
    }
}
