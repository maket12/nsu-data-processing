package org.example.keygen.crypto;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

class CaManagerTest {

    @Test
    @DisplayName("Проверка автоматической генерации и последующего чтения CA из файлов")
    void testLoadOrCreateCa(@TempDir Path tempDir) throws Exception {
        Path caKeyPath = tempDir.resolve("ca.key");
        Path caCertPath = tempDir.resolve("ca.crt");
        String issuer = "CN=TestCA, O=TestOrg, C=RU";

        assertFalse(Files.exists(caKeyPath));
        assertFalse(Files.exists(caCertPath));

        // 1. Создание CA
        CaManager ca1 = CaManager.loadOrCreate(caKeyPath, caCertPath, issuer);
        assertNotNull(ca1);
        assertNotNull(ca1.getCaPrivateKey());
        assertNotNull(ca1.getCaCertificate());
        assertTrue(Files.exists(caKeyPath));
        assertTrue(Files.exists(caCertPath));

        // 2. Повторное чтение из созданных файлов
        CaManager ca2 = CaManager.loadOrCreate(caKeyPath, caCertPath, issuer);
        assertNotNull(ca2);
        assertArrayEquals(ca1.getCaPrivateKey().getEncoded(), ca2.getCaPrivateKey().getEncoded());
        assertArrayEquals(ca1.getCaCertificate().getEncoded(), ca2.getCaCertificate().getEncoded());

        // Проверка самоподписи CA
        ca2.getCaCertificate().verify(ca2.getCaCertificate().getPublicKey());
    }
}
