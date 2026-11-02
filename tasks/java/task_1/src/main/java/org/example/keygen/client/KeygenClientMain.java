package org.example.keygen.client;

/**
 * Консольная точка входа для клиента.
 */
public class KeygenClientMain {

    public static void main(String[] args) {
        ClientConfig config = ClientConfig.parse(args);

        try {
            System.out.printf("Подключение к серверу %s:%d для запроса ключей имени '%s'...%n",
                    config.host(), config.port(), config.name());

            KeygenClient client = new KeygenClient();
            KeygenClient.ExecutionResult result = client.execute(config);

            if (result.aborted()) {
                System.out.println("Клиент успешно завершил работу в аварийном режиме (--abort).");
            } else {
                System.out.println("Ключи и сертификат успешно получены и сохранены!");
            }
        } catch (Exception e) {
            System.err.println("Ошибка выполнения клиента: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
