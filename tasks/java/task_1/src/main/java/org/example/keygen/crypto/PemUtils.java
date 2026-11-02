package org.example.keygen.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Utility methods for encoding, decoding, and parsing RSA keys and certificates in PEM format.
 */
public final class PemUtils {

    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN (?:RSA )?PRIVATE KEY-----[\\r\\n]+([A-Za-z0-9+/=\\r\\n]+)[\\r\\n]+-----END (?:RSA )?PRIVATE KEY-----"
    );

    private static final Pattern CERTIFICATE_PATTERN = Pattern.compile(
            "-----BEGIN CERTIFICATE-----[\\r\\n]+([A-Za-z0-9+/=\\r\\n]+)[\\r\\n]+-----END CERTIFICATE-----"
    );

    private PemUtils() {
    }

    /**
     * Converts a private key into PKCS#8 PEM string.
     *
     * @param privateKey private key
     * @return PEM formatted string
     */
    public static String toPem(PrivateKey privateKey) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(privateKey.getEncoded());
        return BEGIN_PRIVATE_KEY + "\n" + base64 + "\n" + END_PRIVATE_KEY;
    }

    /**
     * Converts an X.509 certificate into PEM string.
     *
     * @param certificate X.509 certificate
     * @return PEM formatted string
     * @throws CertificateException on certificate encoding failure
     */
    public static String toPem(X509Certificate certificate) throws CertificateException {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded());
        return BEGIN_CERTIFICATE + "\n" + base64 + "\n" + END_CERTIFICATE;
    }

    /**
     * Parses a private key from PEM string (supports PKCS#8 and PKCS#1).
     *
     * @param pemContent PEM content
     * @return parsed {@link PrivateKey}
     * @throws IOException on I/O error or invalid format
     */
    public static PrivateKey parsePrivateKey(String pemContent) throws IOException {
        try (PEMParser pemParser = new PEMParser(new StringReader(pemContent))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki) {
                return converter.getPrivateKey(pki);
            } else if (object instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }
        }

        // Fallback parsing via standard PKCS8EncodedKeySpec
        Matcher matcher = PRIVATE_KEY_PATTERN.matcher(pemContent);
        if (matcher.find()) {
            String base64 = matcher.group(1).replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(base64);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IOException("Failed to decode private key: " + e.getMessage(), e);
            }
        }

        throw new IOException("No valid private key PEM block found in input.");
    }

    /**
     * Parses an X.509 certificate from PEM string using standard CertificateFactory.
     *
     * @param pemContent PEM string
     * @return parsed {@link X509Certificate}
     * @throws CertificateException on certificate parsing error
     */
    public static X509Certificate parseCertificate(String pemContent) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pemContent.getBytes(StandardCharsets.US_ASCII))
        );
    }

    /**
     * Extracts the private key PEM block from wire payload.
     *
     * @param wirePayload wire response string
     * @return private key PEM string
     * @throws IllegalArgumentException if private key block is not found
     */
    public static String extractPrivateKeyPem(String wirePayload) {
        Matcher matcher = PRIVATE_KEY_PATTERN.matcher(wirePayload);
        if (matcher.find()) {
            return matcher.group(0);
        }
        throw new IllegalArgumentException("Private key not found in server response");
    }

    /**
     * Extracts the certificate PEM block from wire payload.
     *
     * @param wirePayload wire response string
     * @return certificate PEM string
     * @throws IllegalArgumentException if certificate block is not found
     */
    public static String extractCertificatePem(String wirePayload) {
        Matcher matcher = CERTIFICATE_PATTERN.matcher(wirePayload);
        if (matcher.find()) {
            return matcher.group(0);
        }
        throw new IllegalArgumentException("X.509 certificate not found in server response");
    }
}
