package org.example.keygen.client;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import org.example.keygen.crypto.PemUtils;

/**
 * Сетевой клиент для взаимодействия с сервисом генерации ключей по TCP.
 */
public class KeygenClient {

    public record ExecutionResult(
            boolean aborted,
            Path keyFile,
            Path certFile,
            String privateKeyPem,
            String certificatePem
    ) {}

    /**
     * Выполняет запрос к серверу в соответствии с переданной конфигурацией.
     *
     * @param config настройки подключения и опции
     * @return результат выполнения {@link ExecutionResult}
     * @throws Exception при ошибках соединения, чтения или записи файлов
     */
    public ExecutionResult execute(ClientConfig config) throws Exception {
        Objects.requireNonNull(config, "config cannot be null");

        try (Socket socket = new Socket(config.host(), config.port())) {
            OutputStream out = socket.getOutputStream();

            // 1. Отправляем имя (ASCII строка, заканчивающаяся 0x00)
            byte[] nameBytes = config.name().getBytes(StandardCharsets.US_ASCII);
            out.write(nameBytes);
            out.write(0); // завершающий нулевой байт
            out.flush();

            // 2. Имитация аварийного завершения клиента
            if (config.abort()) {
                System.out.println("[Client] Режим --abort: соединение разорвано сразу после отправки запроса.");
                return new ExecutionResult(true, null, null, null, null);
            }

            // 3. Имитация медленного клиента
            if (config.delaySeconds() > 0) {
                System.out.printf("[Client] Режим --delay: пауза %d сек перед считыванием ответа...%n", config.delaySeconds());
                Thread.sleep(config.delaySeconds() * 1000L);
            }

            // 4. Считывание ответа до закрытия сокета сервером (EOF)
            InputStream in = socket.getInputStream();
            byte[] responseBytes = in.readAllBytes();
            if (responseBytes.length == 0) {
                throw new IOException("Сервер закрыл соединение без передачи данных.");
            }

            String wirePayload = new String(responseBytes, StandardCharsets.UTF_8);

            // 5. Извлечение PEM блоков закрытого ключа и сертификата
            String keyPem = PemUtils.extractPrivateKeyPem(wirePayload);
            String certPem = PemUtils.extractCertificatePem(wirePayload);

            // 6. Сохранение в .key и .crt файлы
            Path outDir = config.outDir();
            if (!Files.exists(outDir)) {
                Files.createDirectories(outDir);
            }

            Path keyFile = outDir.resolve(config.name() + ".key");
            Path certFile = outDir.resolve(config.name() + ".crt");

            Files.writeString(keyFile, keyPem);
            Files.writeString(certFile, certPem);

            System.out.println("[Client] Закрытый ключ сохранен в: " + keyFile.toAbsolutePath());
            System.out.println("[Client] Сертификат сохранен в:  " + certFile.toAbsolutePath());

            return new ExecutionResult(false, keyFile, certFile, keyPem, certPem);
        }
    }
}
