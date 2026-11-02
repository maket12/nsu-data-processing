package org.example.keygen.crypto;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import org.example.keygen.common.KeyCertPair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {

    @Test
    @DisplayName("Проверка генерации клиентской пары ключей и валидации выданного X.509 сертификата")
    void testClientKeyAndCertificateGeneration(@TempDir Path tempDir) throws Exception {
        Path caKeyPath = tempDir.resolve("ca.key");
        Path caCertPath = tempDir.resolve("ca.crt");
        CaManager caManager = CaManager.loadOrCreate(caKeyPath, caCertPath, "CN=RootCA, O=Test, C=RU");

        // Для ускорения unit-теста используем размер 2048 бит
        CryptoService cryptoService = new CryptoService(caManager, 2048);

        String clientName = "john_doe";
        KeyCertPair result = cryptoService.generate(clientName);

        assertNotNull(result);
        assertNotNull(result.privateKeyPem());
        assertNotNull(result.certificatePem());

        // Проверяем сертификат
        X509Certificate clientCert = PemUtils.parseCertificate(result.certificatePem());
        assertNotNull(clientCert);

        // 1. Проверка Subject DN
        assertTrue(clientCert.getSubjectX500Principal().getName().contains("CN=john_doe"));

        // 2. Проверка подписи сертификата открытым ключом CA
        clientCert.verify(caManager.getCaCertificate().getPublicKey());

        // 3. Проверка срока действия
        clientCert.checkValidity();
    }
}
