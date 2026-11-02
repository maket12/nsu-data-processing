package org.example.keygen.client;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Command-line options for the keygen client.
 */
public record ClientConfig(
        String host,
        int port,
        String name,
        Path outDir,
        int delaySeconds,
        boolean abort
) {
    public static final String DEFAULT_HOST = "localhost";
    public static final int DEFAULT_PORT = 8080;
    public static final String DEFAULT_NAME = "client";

    public static ClientConfig parse(String[] args) {
        String host = DEFAULT_HOST;
        int port = DEFAULT_PORT;
        String name = DEFAULT_NAME;
        Path outDir = Paths.get(".");
        int delaySeconds = 0;
        boolean abort = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--host":
                    if (++i < args.length) host = args[i];
                    break;
                case "--port":
                    if (++i < args.length) port = Integer.parseInt(args[i]);
                    break;
                case "--name":
                    if (++i < args.length) name = args[i];
                    break;
                case "--out-dir":
                    if (++i < args.length) outDir = Paths.get(args[i]);
                    break;
                case "--delay":
                    if (++i < args.length) delaySeconds = Integer.parseInt(args[i]);
                    break;
                case "--abort":
                    abort = true;
                    break;
                case "--help":
                case "-h":
                    printHelpAndExit();
                    break;
                default:
                    System.err.println("Warning: Unknown argument " + args[i]);
            }
        }

        return new ClientConfig(host, port, name, outDir, delaySeconds, abort);
    }

    private static void printHelpAndExit() {
        System.out.println("Usage: java KeygenClientMain [options]");
        System.out.println("Options:");
        System.out.println("  --host <host>      Server host or IP (default: localhost)");
        System.out.println("  --port <port>      Server port (default: 8080)");
        System.out.println("  --name <name>      Subject name for certificate (default: client)");
        System.out.println("  --out-dir <path>   Output directory for credentials (default: current dir)");
        System.out.println("  --delay <sec>      Delay in seconds before reading response (slow client)");
        System.out.println("  --abort            Abort connection immediately after sending request");
        System.exit(0);
    }
}
