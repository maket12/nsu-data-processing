package org.example.keygen.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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

/**
 * Управляет ключом и сертификатом Центра Сертификации (CA).
 * Загружает существующий CA из файлов или автоматически генерирует новый, если файлы отсутствуют.
 */
public class CaManager {

    private final PrivateKey caPrivateKey;
    private final X509Certificate caCertificate;
    private final X500Name issuerName;

    public CaManager(PrivateKey caPrivateKey, X509Certificate caCertificate) {
        this.caPrivateKey = Objects.requireNonNull(caPrivateKey, "caPrivateKey cannot be null");
        this.caCertificate = Objects.requireNonNull(caCertificate, "caCertificate cannot be null");
        this.issuerName = new X500Name(caCertificate.getSubjectX500Principal().getName());
    }

    /**
     * Загружает CA из указанных путей. Если файлы отсутствуют, генерирует новую пару и сертификат CA,
     * сохраняя их по указанным путям.
     *
     * @param caKeyPath путь к файлу закрытого ключа CA
     * @param caCertPath путь к файлу сертификата CA
     * @param defaultIssuerName имя издателя по умолчанию (если требуется генерация)
     * @return инициализированный экземпляр {@link CaManager}
     * @throws Exception при ошибках генерации, чтения или сохранения файлов
     */
    public static CaManager loadOrCreate(Path caKeyPath, Path caCertPath, String defaultIssuerName) throws Exception {
        if (Files.exists(caKeyPath) && Files.exists(caCertPath)) {
            // Читаем существующий CA
            String keyContent = Files.readString(caKeyPath);
            PrivateKey privateKey = PemUtils.parsePrivateKey(keyContent);

            X509Certificate cert;
            try (InputStream in = Files.newInputStream(caCertPath)) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                cert = (X509Certificate) factory.generateCertificate(in);
            }
            return new CaManager(privateKey, cert);
        }

        // Автоматическая генерация нового CA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096, new SecureRandom());
        KeyPair caKeyPair = kpg.generateKeyPair();

        X500Name issuer = new X500Name(defaultIssuerName);
        BigInteger serial = new BigInteger(159, new SecureRandom());
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(5, ChronoUnit.MINUTES));
        Date notAfter = Date.from(now.plus(3650, ChronoUnit.DAYS)); // 10 лет

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                issuer,
                caKeyPair.getPublic()
        );

        // Расширения для CA: BasicConstraints(isCA = true) и KeyUsage
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(caKeyPair.getPrivate());
        X509CertificateHolder holder = certBuilder.build(signer);
        X509Certificate caCert = new JcaX509CertificateConverter().getCertificate(holder);

        // Сохраняем сгенерированные файлы
        if (caKeyPath.getParent() != null) {
            Files.createDirectories(caKeyPath.getParent());
        }
        if (caCertPath.getParent() != null) {
            Files.createDirectories(caCertPath.getParent());
        }

        Files.writeString(caKeyPath, PemUtils.toPem(caKeyPair.getPrivate()));
        Files.writeString(caCertPath, PemUtils.toPem(caCert));

        return new CaManager(caKeyPair.getPrivate(), caCert);
    }

    public PrivateKey getCaPrivateKey() {
        return caPrivateKey;
    }

    public X509Certificate getCaCertificate() {
        return caCertificate;
    }

    public X500Name getIssuerName() {
        return issuerName;
    }
}
