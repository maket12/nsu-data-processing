package org.example.keygen.common;

import java.util.Objects;

/**
 * Data Transfer Object holding generated RSA private key (PKCS#8 PEM)
 * and signed X.509 certificate (PEM).
 *
 * @param privateKeyPem private key in PEM format (PKCS#8)
 * @param certificatePem X.509 certificate in PEM format
 */
public record KeyCertPair(String privateKeyPem, String certificatePem) {
    public KeyCertPair {
        Objects.requireNonNull(privateKeyPem, "privateKeyPem cannot be null");
        Objects.requireNonNull(certificatePem, "certificatePem cannot be null");
    }

    /**
     * Serializes key pair and certificate into a single PEM wire payload.
     *
     * @return payload containing private key and certificate PEM blocks
     */
    public String toWirePayload() {
        return privateKeyPem.trim() + System.lineSeparator() + certificatePem.trim() + System.lineSeparator();
    }
}
