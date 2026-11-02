package org.example.keygen.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;

/**
 * Инкапсулирует состояние одного клиентского соединения в NIO Selector.
 */
public class ClientSession {

    public enum State {
        READING_NAME,
        WAITING_CRYPTO,
        WRITING_RESPONSE,
        COMPLETED,
        CLOSED
    }

    public static final int MAX_NAME_LENGTH = 256;

    private final SocketChannel channel;
    private final ByteArrayOutputStream nameBytes = new ByteArrayOutputStream();
    private volatile State state = State.READING_NAME;
    private String clientName;
    private ByteBuffer writeBuffer;
    private SelectionKey selectionKey;

    public ClientSession(SocketChannel channel) {
        this.channel = channel;
    }

    /**
     * Читает байты из входного буфера до нахождения терминального нуля '\0'.
     *
     * @param buffer буфер с только что прочитанными данными
     * @return {@code true}, если имя полностью прочитано (встретился 0x00), иначе {@code false}
     * @throws IllegalArgumentException если длина имени превысила {@link #MAX_NAME_LENGTH}
     */
    public boolean readNameBytes(ByteBuffer buffer) {
        while (buffer.hasRemaining()) {
            byte b = buffer.get();
            if (b == 0) {
                this.clientName = nameBytes.toString(StandardCharsets.US_ASCII).trim();
                this.state = State.WAITING_CRYPTO;
                return true;
            }
            nameBytes.write(b);
            if (nameBytes.size() > MAX_NAME_LENGTH) {
                throw new IllegalArgumentException("Имя клиента превышает лимит " + MAX_NAME_LENGTH + " байт");
            }
        }
        return false;
    }

    /**
     * Инициализирует буфер отправки подготовленными PEM-данными.
     *
     * @param payload строковые данные для отправки
     */
    public void prepareOutboundPayload(String payload) {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        this.writeBuffer = ByteBuffer.wrap(bytes);
        this.state = State.WRITING_RESPONSE;
    }

    /**
     * Сбрасывает данные из writeBuffer в сетевой канал.
     *
     * @return {@code true}, если все данные полностью отправлены клиенту, иначе {@code false}
     * @throws IOException при ошибках сокета
     */
    public boolean flush() throws IOException {
        if (writeBuffer == null) {
            return true;
        }
        channel.write(writeBuffer);
        if (!writeBuffer.hasRemaining()) {
            this.state = State.COMPLETED;
            return true;
        }
        return false;
    }

    public void close() {
        this.state = State.CLOSED;
        try {
            if (channel.isOpen()) {
                channel.close();
            }
        } catch (IOException ignored) {
        }
    }

    public SocketChannel getChannel() {
        return channel;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public String getClientName() {
        return clientName;
    }

    public SelectionKey getSelectionKey() {
        return selectionKey;
    }

    public void setSelectionKey(SelectionKey selectionKey) {
        this.selectionKey = selectionKey;
    }
}
