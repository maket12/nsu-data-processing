package org.example.keygen.common;

import java.util.Objects;

/**
 * DTO, содержащий сгенерированный закрытый ключ RSA (PKCS#8 PEM)
 * и подписанный сертификат X.509 (PEM).
 *
 * @param privateKeyPem закрытый ключ в формате PEM (PKCS#8)
 * @param certificatePem сертификат X.509 в формате PEM
 */
public record KeyCertPair(String privateKeyPem, String certificatePem) {
    public KeyCertPair {
        Objects.requireNonNull(privateKeyPem, "privateKeyPem cannot be null");
        Objects.requireNonNull(certificatePem, "certificatePem cannot be null");
    }

    /**
     * Формирует единый поток PEM для передачи по сети клиенту.
     *
     * @return строковый блок с закрытым ключом и сертификатом
     */
    public String toWirePayload() {
        return privateKeyPem.trim() + System.lineSeparator() + certificatePem.trim() + System.lineSeparator();
    }
}
