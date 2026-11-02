package org.example.keygen.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.example.keygen.common.KeyCertPair;

/**
 * Сервис генерации ключевых пар RSA и выпуска сертификатов X.509.
 */
public class CryptoService {

    public static final int DEFAULT_KEY_SIZE = 8192;

    private final CaManager caManager;
    private final int keySize;
    private final SecureRandom secureRandom;

    public CryptoService(CaManager caManager) {
        this(caManager, DEFAULT_KEY_SIZE);
    }

    public CryptoService(CaManager caManager, int keySize) {
        this.caManager = Objects.requireNonNull(caManager, "caManager cannot be null");
        this.keySize = keySize;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Генерирует пару RSA ключей (8192 бит по умолчанию) и выпускает подписанный сертификат X.509
     * для указанного имени клиента.
     *
     * @param clientName имя клиента (ASCII строка)
     * @return {@link KeyCertPair} с закрытым ключом и сертификатом в формате PEM
     * @throws NoSuchAlgorithmException при ошибках криптопровайдера
     * @throws OperatorCreationException при ошибках инициализации подписи
     * @throws CertificateException при ошибках создания сертификата
     */
    public KeyCertPair generate(String clientName)
            throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {

        // 1. Генерация пары RSA ключей
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize, secureRandom);
        KeyPair clientKeyPair = kpg.generateKeyPair();

        // 2. Построение сертификата X.509
        X500Name subjectName = formatSubjectName(clientName);
        BigInteger serialNumber = new BigInteger(159, secureRandom);

        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(5, ChronoUnit.MINUTES));
        Date notAfter = Date.from(now.plus(365, ChronoUnit.DAYS));

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caManager.getIssuerName(),
                serialNumber,
                notBefore,
                notAfter,
                subjectName,
                clientKeyPair.getPublic()
        );

        // Расширения X.509: конечный сертификат (не CA) и использование ключа
        try {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certBuilder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment)
            );
        } catch (Exception e) {
            throw new CertificateException("Не удалось добавить расширения к сертификату", e);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(caManager.getCaPrivateKey());

        X509CertificateHolder holder = certBuilder.build(signer);
        X509Certificate clientCert = new JcaX509CertificateConverter().getCertificate(holder);

        // 3. Сериализация в PEM
        String privateKeyPem = PemUtils.toPem(clientKeyPair.getPrivate());
        String certificatePem = PemUtils.toPem(clientCert);

        return new KeyCertPair(privateKeyPem, certificatePem);
    }

    private X500Name formatSubjectName(String clientName) {
        if (clientName.contains("=")) {
            return new X500Name(clientName);
        }
        return new X500Name("CN=" + clientName);
    }

    public int getKeySize() {
        return keySize;
    }
}
