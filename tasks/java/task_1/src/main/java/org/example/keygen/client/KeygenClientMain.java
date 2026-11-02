package org.example.keygen.client;

/**
 * Command-line entry point for the keygen client.
 */
public class KeygenClientMain {

    public static void main(String[] args) {
        ClientConfig config = ClientConfig.parse(args);

        try {
            System.out.printf("[Client] Connecting to %s:%d to request credentials for '%s'...%n",
                    config.host(), config.port(), config.name());

            KeygenClient client = new KeygenClient();
            KeygenClient.ExecutionResult result = client.execute(config);

            if (result.aborted()) {
                System.out.println("[Client] Successfully completed in abort mode (--abort).");
            } else {
                System.out.println("[Client] Key pair and certificate successfully received and stored!");
            }
        } catch (Exception e) {
            System.err.println("[Client] Error executing client: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
