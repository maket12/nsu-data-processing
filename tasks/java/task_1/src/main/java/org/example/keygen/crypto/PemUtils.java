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
 * Утилиты для кодирования, декодирования и парсинга объектов ключей и сертификатов в формат PEM.
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
     * Преобразует закрытый ключ в строку PEM (PKCS#8).
     *
     * @param privateKey закрытый ключ
     * @return строка в формате PEM
     */
    public static String toPem(PrivateKey privateKey) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(privateKey.getEncoded());
        return BEGIN_PRIVATE_KEY + "\n" + base64 + "\n" + END_PRIVATE_KEY;
    }

    /**
     * Преобразует сертификат X.509 в строку PEM.
     *
     * @param certificate сертификат
     * @return строка в формате PEM
     * @throws CertificateException при ошибке кодирования сертификата
     */
    public static String toPem(X509Certificate certificate) throws CertificateException {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded());
        return BEGIN_CERTIFICATE + "\n" + base64 + "\n" + END_CERTIFICATE;
    }

    /**
     * Читает закрытый ключ из строки PEM (поддерживает PKCS#8 и PKCS#1).
     *
     * @param pemContent содержимое в формате PEM
     * @return объект {@link PrivateKey}
     * @throws IOException при ошибках ввода-вывода или неверном формате
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

        // Запасной вариант парсинга через стандартный PKCS8EncodedKeySpec
        Matcher matcher = PRIVATE_KEY_PATTERN.matcher(pemContent);
        if (matcher.find()) {
            String base64 = matcher.group(1).replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(base64);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new IOException("Не удалось декодировать закрытый ключ: " + e.getMessage(), e);
            }
        }

        throw new IOException("В предоставленной строке не найден валидный блок закрытого ключа PEM.");
    }

    /**
     * Читает сертификат X.509 из строки PEM с помощью стандартной CertificateFactory.
     *
     * @param pemContent содержимое в формате PEM
     * @return объект {@link X509Certificate}
     * @throws CertificateException при ошибках декодирования сертификата
     */
    public static X509Certificate parseCertificate(String pemContent) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(pemContent.getBytes(StandardCharsets.US_ASCII))
        );
    }

    /**
     * Извлекает блок закрытого ключа из объединенного ответа сервера.
     *
     * @param wirePayload полученный текст ответа
     * @return строка PEM закрытого ключа
     * @throws IllegalArgumentException если блок закрытого ключа не найден
     */
    public static String extractPrivateKeyPem(String wirePayload) {
        Matcher matcher = PRIVATE_KEY_PATTERN.matcher(wirePayload);
        if (matcher.find()) {
            return matcher.group(0);
        }
        throw new IllegalArgumentException("Закрытый ключ не найден в сетевом ответе");
    }

    /**
     * Извлекает блок сертификата из объединенного ответа сервера.
     *
     * @param wirePayload полученный текст ответа
     * @return строка PEM сертификата
     * @throws IllegalArgumentException если блок сертификата не найден
     */
    public static String extractCertificatePem(String wirePayload) {
        Matcher matcher = CERTIFICATE_PATTERN.matcher(wirePayload);
        if (matcher.find()) {
            return matcher.group(0);
        }
        throw new IllegalArgumentException("Сертификат X.509 не найден в сетевом ответе");
    }
}
