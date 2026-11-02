package org.example.keygen.server;

import org.example.keygen.crypto.CaManager;
import org.example.keygen.crypto.CryptoService;

/**
 * Точка входа в сервер генерации ключей.
 */
public class KeygenServerMain {

    public static void main(String[] args) {
        ServerConfig config = ServerConfig.parse(args);

        try {
            System.out.println("=== Запуск сервиса генерации ключей RSA ===");
            System.out.println("Инициализация Центра Сертификации (CA)...");
            CaManager caManager = CaManager.loadOrCreate(
                    config.caKeyPath(),
                    config.caCertPath(),
                    config.issuerName()
            );
            System.out.println("CA успешно загружен: " + caManager.getCaCertificate().getSubjectX500Principal());

            CryptoService cryptoService = new CryptoService(caManager, config.keySize());
            KeygenServer server = new KeygenServer(config, cryptoService);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nОстановка сервера...");
                server.close();
                System.out.println("Сервер успешно остановлен.");
            }));

            server.start();

            // Держим основной поток живым до прерывания
            Thread.currentThread().join();

        } catch (InterruptedException e) {
            System.out.println("Получен сигнал завершения.");
        } catch (Exception e) {
            System.err.println("Критическая ошибка запуска сервера: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
