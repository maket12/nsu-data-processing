package org.example.keygen.client;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Параметры командной строки для клиента генерации ключей.
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
                    System.err.println("Предупреждение: Неизвестный аргумент " + args[i]);
            }
        }

        return new ClientConfig(host, port, name, outDir, delaySeconds, abort);
    }

    private static void printHelpAndExit() {
        System.out.println("Использование: java KeygenClientMain [опции]");
        System.out.println("Опции:");
        System.out.println("  --host <host>      DNS-имя или IP сервера (по умолчанию: localhost)");
        System.out.println("  --port <port>      Порт сервера (по умолчанию: 8080)");
        System.out.println("  --name <name>      Имя для сертификата (по умолчанию: client)");
        System.out.println("  --out-dir <path>   Директория сохранения файлов (по умолчанию: текущая)");
        System.out.println("  --delay <sec>      Задержка в секундах перед вычитыванием ответа (медленный клиент)");
        System.out.println("  --abort            Завершение работы без считывания ответа (авария)");
        System.exit(0);
    }
}
