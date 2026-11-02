package org.example.keygen.server;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.example.keygen.client.ClientConfig;
import org.example.keygen.client.KeygenClient;
import org.example.keygen.crypto.CaManager;
import org.example.keygen.crypto.CryptoService;
import org.example.keygen.crypto.PemUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

class KeygenServerIntegrationTest {

    @TempDir
    Path tempDir;

    private KeygenServer server;
    private CaManager caManager;
    private int serverPort;

    @BeforeEach
    void setUp() throws Exception {
        Path caKeyPath = tempDir.resolve("ca.key");
        Path caCertPath = tempDir.resolve("ca.crt");
        caManager = CaManager.loadOrCreate(caKeyPath, caCertPath, "CN=TestRootCA, O=TestLab, C=US");

        // Use 2048-bit key size for fast test execution
        CryptoService cryptoService = new CryptoService(caManager, 2048);

        ServerConfig config = new ServerConfig(
                "127.0.0.1",
                0, // ephemeral port
                4,
                "CN=TestRootCA, O=TestLab, C=US",
                caKeyPath,
                caCertPath,
                2048
        );

        server = new KeygenServer(config, cryptoService);
        server.start();
        serverPort = server.getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    @DisplayName("Successful key exchange by a normal client")
    void testSuccessfulClientExchange() throws Exception {
        KeygenClient client = new KeygenClient();
        ClientConfig config = new ClientConfig("127.0.0.1", serverPort, "alice", tempDir, 0, false);

        KeygenClient.ExecutionResult result = client.execute(config);

        assertFalse(result.aborted());
        assertNotNull(result.keyFile());
        assertNotNull(result.certFile());
        assertTrue(result.keyFile().toFile().exists());
        assertTrue(result.certFile().toFile().exists());

        // Certificate validation
        X509Certificate cert = PemUtils.parseCertificate(result.certificatePem());
        assertTrue(cert.getSubjectX500Principal().getName().contains("CN=alice"));
        cert.verify(caManager.getCaCertificate().getPublicKey());
    }

    @Test
    @DisplayName("Deduplication of concurrent requests with identical name")
    void testConcurrentDuplicateRequests() throws Exception {
        int threadsCount = 5;
        ExecutorService executor = Executors.newFixedThreadPool(threadsCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadsCount);

        List<String> receivedKeys = Collections.synchronizedList(new ArrayList<>());
        List<String> receivedCerts = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < threadsCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    KeygenClient client = new KeygenClient();
                    ClientConfig config = new ClientConfig("127.0.0.1", serverPort, "same_user", tempDir, 0, false);
                    KeygenClient.ExecutionResult res = client.execute(config);
                    receivedKeys.add(res.privateKeyPem());
                    receivedCerts.add(res.certificatePem());
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(15, TimeUnit.SECONDS));
        executor.shutdown();

        assertEquals(threadsCount, receivedKeys.size());
        assertEquals(threadsCount, receivedCerts.size());

        // All clients must receive the exact same key and certificate
        String firstKey = receivedKeys.get(0);
        String firstCert = receivedCerts.get(0);

        for (String key : receivedKeys) {
            assertEquals(firstKey, key);
        }
        for (String cert : receivedCerts) {
            assertEquals(firstCert, cert);
        }

        // Cache must have exactly 1 entry
        assertEquals(1, server.getCachedKeysCount());
    }

    @Test
    @DisplayName("Slow client simulation (--delay) does not block parallel requests")
    void testSlowClientDoesNotBlockFastClients() throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch slowStarted = new CountDownLatch(1);
        CountDownLatch fastDone = new CountDownLatch(1);

        // Slow client with 2-second delay
        executor.submit(() -> {
            try {
                slowStarted.countDown();
                KeygenClient slowClient = new KeygenClient();
                ClientConfig config = new ClientConfig("127.0.0.1", serverPort, "slow_user", tempDir, 2, false);
                slowClient.execute(config);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        slowStarted.await();

        // Fast client should complete immediately while the slow client is waiting
        executor.submit(() -> {
            try {
                KeygenClient fastClient = new KeygenClient();
                ClientConfig config = new ClientConfig("127.0.0.1", serverPort, "fast_user", tempDir, 0, false);
                KeygenClient.ExecutionResult res = fastClient.execute(config);
                assertNotNull(res.privateKeyPem());
                fastDone.countDown();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        assertTrue(fastDone.await(5, TimeUnit.SECONDS), "Fast client must not be blocked by slow client");
        executor.shutdown();
    }

    @Test
    @DisplayName("Client crash simulation (--abort) does not crash the server")
    void testClientAbortSimulation() throws Exception {
        KeygenClient client = new KeygenClient();
        ClientConfig config = new ClientConfig("127.0.0.1", serverPort, "aborted_user", tempDir, 0, true);

        KeygenClient.ExecutionResult result = client.execute(config);
        assertTrue(result.aborted());

        // Allow server time to finish calculation and save to cache
        Thread.sleep(500);

        // Subsequent query by a normal client should immediately retrieve cached result
        ClientConfig normalConfig = new ClientConfig("127.0.0.1", serverPort, "aborted_user", tempDir, 0, false);
        KeygenClient.ExecutionResult normalResult = client.execute(normalConfig);

        assertFalse(normalResult.aborted());
        assertNotNull(normalResult.privateKeyPem());
        assertNotNull(normalResult.certificatePem());
    }

    @Test
    @DisplayName("Support 100+ concurrent connections via NIO Selector")
    void testHundredConcurrentClients() throws Exception {
        int clientsCount = 100;
        ExecutorService executor = Executors.newFixedThreadPool(20);
        CountDownLatch latch = new CountDownLatch(clientsCount);
        List<Boolean> successFlags = Collections.synchronizedList(new ArrayList<>());

        // Prepopulate cache to avoid heavy CPU load in test
        KeygenClient warmupClient = new KeygenClient();
        warmupClient.execute(new ClientConfig("127.0.0.1", serverPort, "load_user", tempDir, 0, false));

        for (int i = 0; i < clientsCount; i++) {
            executor.submit(() -> {
                try (Socket socket = new Socket("127.0.0.1", serverPort)) {
                    OutputStream out = socket.getOutputStream();
                    out.write("load_user".getBytes(StandardCharsets.US_ASCII));
                    out.write(0);
                    out.flush();

                    InputStream in = socket.getInputStream();
                    byte[] data = in.readAllBytes();
                    if (data.length > 0 && new String(data, StandardCharsets.UTF_8).contains("BEGIN CERTIFICATE")) {
                        successFlags.add(true);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(20, TimeUnit.SECONDS), "All 100 clients must receive responses successfully");
        assertEquals(clientsCount, successFlags.size(), "All 100 clients must receive valid certificates");
        executor.shutdown();
    }
}
