package org.example.keygen.server;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Server configuration parsed from command-line arguments.
 */
public record ServerConfig(
        String host,
        int port,
        int threads,
        String issuerName,
        Path caKeyPath,
        Path caCertPath,
        int keySize
) {
    public static final String DEFAULT_HOST = "0.0.0.0";
    public static final int DEFAULT_PORT = 8080;
    public static final String DEFAULT_ISSUER = "CN=KeygenRootCA, O=KeygenService, C=US";
    public static final String DEFAULT_CA_KEY = "ca.key";
    public static final String DEFAULT_CA_CERT = "ca.crt";
    public static final int DEFAULT_KEY_SIZE = 8192;

    public static ServerConfig parse(String[] args) {
        String host = DEFAULT_HOST;
        int port = DEFAULT_PORT;
        int threads = Math.max(1, Runtime.getRuntime().availableProcessors());
        String issuer = DEFAULT_ISSUER;
        Path caKey = Paths.get(DEFAULT_CA_KEY);
        Path caCert = Paths.get(DEFAULT_CA_CERT);
        int keySize = DEFAULT_KEY_SIZE;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--host":
                    if (++i < args.length) host = args[i];
                    break;
                case "--port":
                    if (++i < args.length) port = Integer.parseInt(args[i]);
                    break;
                case "--threads":
                    if (++i < args.length) threads = Integer.parseInt(args[i]);
                    break;
                case "--issuer":
                    if (++i < args.length) issuer = args[i];
                    break;
                case "--ca-key":
                    if (++i < args.length) caKey = Paths.get(args[i]);
                    break;
                case "--ca-cert":
                    if (++i < args.length) caCert = Paths.get(args[i]);
                    break;
                case "--key-size":
                    if (++i < args.length) keySize = Integer.parseInt(args[i]);
                    break;
                case "--help":
                case "-h":
                    printHelpAndExit();
                    break;
                default:
                    System.err.println("Warning: Unknown argument " + args[i]);
            }
        }

        return new ServerConfig(host, port, threads, issuer, caKey, caCert, keySize);
    }

    private static void printHelpAndExit() {
        System.out.println("Usage: java KeygenServerMain [options]");
        System.out.println("Options:");
        System.out.println("  --host <host>       Socket bind address (default: 0.0.0.0)");
        System.out.println("  --port <port>       Server port (default: 8080)");
        System.out.println("  --threads <n>       Number of key generator threads (default: CPU cores)");
        System.out.println("  --issuer <dn>       Issuer Name for X.509 certificates");
        System.out.println("  --ca-key <path>     Path to CA private key (default: ca.key)");
        System.out.println("  --ca-cert <path>    Path to CA certificate (default: ca.crt)");
        System.out.println("  --key-size <bits>   RSA key size in bits (default: 8192)");
        System.exit(0);
    }
}
