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
 * TCP client for interacting with the key generation service.
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
     * Executes request to key generation server based on provided configuration.
     *
     * @param config client configuration
     * @return {@link ExecutionResult} of the execution
     * @throws Exception on connection, I/O, or file errors
     */
    public ExecutionResult execute(ClientConfig config) throws Exception {
        Objects.requireNonNull(config, "config cannot be null");

        try (Socket socket = new Socket(config.host(), config.port())) {
            OutputStream out = socket.getOutputStream();

            // 1. Send name (ASCII string ending with 0x00)
            byte[] nameBytes = config.name().getBytes(StandardCharsets.US_ASCII);
            out.write(nameBytes);
            out.write(0); // terminal null byte
            out.flush();

            // 2. Client crash simulation
            if (config.abort()) {
                System.out.println("[Client] --abort mode: connection severed immediately after sending request.");
                return new ExecutionResult(true, null, null, null, null);
            }

            // 3. Slow client simulation
            if (config.delaySeconds() > 0) {
                System.out.printf("[Client] --delay mode: pausing for %d seconds before reading response...%n", config.delaySeconds());
                Thread.sleep(config.delaySeconds() * 1000L);
            }

            // 4. Read response until server closes socket (EOF)
            InputStream in = socket.getInputStream();
            byte[] responseBytes = in.readAllBytes();
            if (responseBytes.length == 0) {
                throw new IOException("Server closed connection without transmitting data.");
            }

            String wirePayload = new String(responseBytes, StandardCharsets.UTF_8);

            // 5. Extract PEM blocks for private key and certificate
            String keyPem = PemUtils.extractPrivateKeyPem(wirePayload);
            String certPem = PemUtils.extractCertificatePem(wirePayload);

            // 6. Save to .key and .crt files
            Path outDir = config.outDir();
            if (!Files.exists(outDir)) {
                Files.createDirectories(outDir);
            }

            Path keyFile = outDir.resolve(config.name() + ".key");
            Path certFile = outDir.resolve(config.name() + ".crt");

            Files.writeString(keyFile, keyPem);
            Files.writeString(certFile, certPem);

            System.out.println("[Client] Private key saved to: " + keyFile.toAbsolutePath());
            System.out.println("[Client] Certificate saved to: " + certFile.toAbsolutePath());

            return new ExecutionResult(false, keyFile, certFile, keyPem, certPem);
        }
    }
}
