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
    @DisplayName("Verify client key pair generation and X.509 certificate validation")
    void testClientKeyAndCertificateGeneration(@TempDir Path tempDir) throws Exception {
        Path caKeyPath = tempDir.resolve("ca.key");
        Path caCertPath = tempDir.resolve("ca.crt");
        CaManager caManager = CaManager.loadOrCreate(caKeyPath, caCertPath, "CN=RootCA, O=Test, C=US");

        // Use 2048-bit key size for fast unit testing
        CryptoService cryptoService = new CryptoService(caManager, 2048);

        String clientName = "john_doe";
        KeyCertPair result = cryptoService.generate(clientName);

        assertNotNull(result);
        assertNotNull(result.privateKeyPem());
        assertNotNull(result.certificatePem());

        // Verify certificate
        X509Certificate clientCert = PemUtils.parseCertificate(result.certificatePem());
        assertNotNull(clientCert);

        // 1. Verify Subject DN
        assertTrue(clientCert.getSubjectX500Principal().getName().contains("CN=john_doe"));

        // 2. Verify certificate signature using CA public key
        clientCert.verify(caManager.getCaCertificate().getPublicKey());

        // 3. Verify validity period
        clientCert.checkValidity();
    }
}
