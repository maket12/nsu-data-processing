package org.example.keygen.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PemUtilsTest {

    @Test
    @DisplayName("Проверка сериализации и десериализации RSA закрытого ключа в PEM")
    void testPrivateKeyPemRoundtrip() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        String pem = PemUtils.toPem(keyPair.getPrivate());
        assertNotNull(pem);
        assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(pem.endsWith("-----END PRIVATE KEY-----"));

        PrivateKey parsedKey = PemUtils.parsePrivateKey(pem);
        assertNotNull(parsedKey);
        assertArrayEquals(keyPair.getPrivate().getEncoded(), parsedKey.getEncoded());
    }

    @Test
    @DisplayName("Проверка извлечения блоков ключа и сертификата из объединенного ответа")
    void testExtractBlocksFromWirePayload() {
        String dummyPayload = """
                -----BEGIN PRIVATE KEY-----
                MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3
                -----END PRIVATE KEY-----
                
                -----BEGIN CERTIFICATE-----
                MIIDdzCCAl+gAwIBAgIUQ5v0qW2f+
                -----END CERTIFICATE-----
                """;

        String keyPem = PemUtils.extractPrivateKeyPem(dummyPayload);
        String certPem = PemUtils.extractCertificatePem(dummyPayload);

        assertTrue(keyPem.contains("BEGIN PRIVATE KEY"));
        assertTrue(certPem.contains("BEGIN CERTIFICATE"));
    }
}
