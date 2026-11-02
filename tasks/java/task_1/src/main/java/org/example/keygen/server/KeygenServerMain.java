package org.example.keygen.server;

import org.example.keygen.crypto.CaManager;
import org.example.keygen.crypto.CryptoService;

/**
 * Entry point for the RSA Key Generation Server.
 */
public class KeygenServerMain {

    public static void main(String[] args) {
        ServerConfig config = ServerConfig.parse(args);

        try {
            System.out.println("=== Starting RSA Key Generation Service ===");
            System.out.println("Initializing Certificate Authority (CA)...");
            CaManager caManager = CaManager.loadOrCreate(
                    config.caKeyPath(),
                    config.caCertPath(),
                    config.issuerName()
            );
            System.out.println("CA loaded successfully: " + caManager.getCaCertificate().getSubjectX500Principal());

            CryptoService cryptoService = new CryptoService(caManager, config.keySize());
            KeygenServer server = new KeygenServer(config, cryptoService);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\n[Server] Shutting down server...");
                server.close();
                System.out.println("[Server] Server stopped successfully.");
            }));

            server.start();

            // Keep main thread alive until interrupt
            Thread.currentThread().join();

        } catch (InterruptedException e) {
            System.out.println("[Server] Termination signal received.");
        } catch (Exception e) {
            System.err.println("[Server] Fatal error starting server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
