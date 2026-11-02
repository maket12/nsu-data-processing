package org.example.keygen.server;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Конфигурация сервера генерации ключей, получаемая из аргументов командной строки.
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
    public static final String DEFAULT_ISSUER = "CN=KeygenRootCA, O=KeygenService, C=RU";
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
                    System.err.println("Предупреждение: Неизвестный аргумент " + args[i]);
            }
        }

        return new ServerConfig(host, port, threads, issuer, caKey, caCert, keySize);
    }

    private static void printHelpAndExit() {
        System.out.println("Использование: java KeygenServerMain [опции]");
        System.out.println("Опции:");
        System.out.println("  --host <host>       Адрес для привязки сокета (по умолчанию: 0.0.0.0)");
        System.out.println("  --port <port>       Порт сервера (по умолчанию: 8080)");
        System.out.println("  --threads <n>       Количество генерирующих потоков (по умолчанию: число ядер CPU)");
        System.out.println("  --issuer <dn>       Issuer Name для X.509 сертификатов");
        System.out.println("  --ca-key <path>     Путь к закрытому ключу CA (по умолчанию: ca.key)");
        System.out.println("  --ca-cert <path>    Путь к сертификату CA (по умолчанию: ca.crt)");
        System.out.println("  --key-size <bits>   Размер генерируемого ключа RSA (по умолчанию: 8192)");
        System.exit(0);
    }
}
