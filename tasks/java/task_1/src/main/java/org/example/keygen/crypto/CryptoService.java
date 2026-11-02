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
 * Service for generating RSA key pairs and issuing X.509 certificates.
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
     * Generates an RSA key pair (default 8192 bits) and issues a signed X.509 certificate
     * for the provided client name.
     *
     * @param clientName client name (ASCII string)
     * @return {@link KeyCertPair} containing private key and certificate in PEM format
     * @throws NoSuchAlgorithmException on cryptographic algorithm error
     * @throws OperatorCreationException on signature initialization error
     * @throws CertificateException on certificate construction error
     */
    public KeyCertPair generate(String clientName)
            throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {

        // 1. Generate RSA key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize, secureRandom);
        KeyPair clientKeyPair = kpg.generateKeyPair();

        // 2. Build X.509 certificate
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

        // X.509 Extensions: End-entity (isCA = false) and KeyUsage
        try {
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certBuilder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment)
            );
        } catch (Exception e) {
            throw new CertificateException("Failed to add extensions to certificate", e);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .build(caManager.getCaPrivateKey());

        X509CertificateHolder holder = certBuilder.build(signer);
        X509Certificate clientCert = new JcaX509CertificateConverter().getCertificate(holder);

        // 3. Serialize to PEM format
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
