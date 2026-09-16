package com.tinnapat.demo.cbom.gaps;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import javax.crypto.KEM;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Crypto that the Sonar Cryptography plugin has <em>no rule for</em>, kept in the repository on
 * purpose so the demo can show where one scanner stops and another has to take over.
 *
 * <p>None of the following becomes a {@code cryptographic-asset} in {@code cbom.json}:
 * <ul>
 * <li>{@code CertificateFactory} and {@code KeyStore} — no JCA rules exist for either.
 * <li>{@code KeyManagerFactory} / {@code TrustManagerFactory} — the TLS trust model is invisible.
 * <li>{@code JcaX509v3CertificateBuilder} / {@code JcaContentSignerBuilder} — these are the
 * BouncyCastle <em>JCA bridge</em>, and the plugin covers only the light-weight API.
 * <li>{@code javax.crypto.KEM} — the JDK 21+ KEM API has no rule, so ML-KEM used this way
 * disappears even though the same algorithm is detected when driven through the light-weight API.
 * </ul>
 *
 * <p>The certificate and keystore material this class writes under {@code target/demo-pki} is what
 * {@code cbomkit-theia} then picks up with its {@code certificates}, {@code keys} and
 * {@code secrets} plugins — covering the gap from the filesystem side instead of the source side.
 */
public final class ScannerGapDemo implements CryptoDemo {

	/** Demo-only keystore password. Not a secret: the keystore holds a throwaway generated key. */
	private static final char[] KEYSTORE_PASSWORD = "cbom-demo-not-a-secret".toCharArray();

	private final Path outputDirectory;

	public ScannerGapDemo(Path outputDirectory) {
		this.outputDirectory = outputDirectory;
	}

	@Override
	public String ruleGroup() {
		return "(no rule) certificates, keystores, javax.crypto.KEM";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		Files.createDirectories(outputDirectory);

		KeyPair caKeyPair = ecKeyPair();
		KeyPair serverKeyPair = ecKeyPair();
		X509Certificate caCertificate = certificate("CN=CBOM Demo Root CA", caKeyPair, caKeyPair,
				"CN=CBOM Demo Root CA", true, false);
		X509Certificate serverCertificate = certificate("CN=localhost", serverKeyPair, caKeyPair,
				"CN=CBOM Demo Root CA", false, true);
		evidence.ok("JcaX509v3CertificateBuilder", "BC (JCA bridge)",
				"NO rule: signed with " + serverCertificate.getSigAlgName());

		writePem(outputDirectory.resolve("demo-root-ca.crt"), caCertificate);
		writePem(outputDirectory.resolve("demo-server.crt"), serverCertificate);

		certificateFactory(evidence, outputDirectory.resolve("demo-server.crt"));
		keyStore(evidence, serverKeyPair, serverCertificate, caCertificate);
		trustModel(evidence);
		jdkKemApi(evidence);
	}

	/** No {@code CertificateFactory} rule exists, so X.509 parsing never reaches the CBOM. */
	private void certificateFactory(Evidence evidence, Path pem) throws Exception {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		try (var input = Files.newInputStream(pem)) {
			X509Certificate parsed = (X509Certificate) factory.generateCertificate(input);
			evidence.ok("CertificateFactory X.509", factory.getProvider().getName(),
					"NO rule: subject " + parsed.getSubjectX500Principal().getName()
							+ ", key " + parsed.getPublicKey().getAlgorithm());
		}
	}

	/** No {@code KeyStore} rule exists; the PKCS#12 file is left for a filesystem scanner. */
	private void keyStore(Evidence evidence, KeyPair keyPair, X509Certificate server, X509Certificate ca)
			throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, KEYSTORE_PASSWORD);
		keyStore.setKeyEntry("demo-server", keyPair.getPrivate(), KEYSTORE_PASSWORD,
				new X509Certificate[] { server, ca });
		Path path = outputDirectory.resolve("demo-keystore.p12");
		try (OutputStream output = Files.newOutputStream(path)) {
			keyStore.store(output, KEYSTORE_PASSWORD);
		}
		evidence.ok("KeyStore PKCS12", keyStore.getProvider().getName(),
				"NO rule: wrote " + path.getFileName() + " (" + Files.size(path) + " bytes)");
	}

	private void trustModel(Evidence evidence) throws Exception {
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX");
		trustManagerFactory.init((KeyStore) null);
		evidence.ok("KeyManagerFactory/TrustManagerFactory",
				keyManagerFactory.getProvider().getName() + "/" + trustManagerFactory.getProvider().getName(),
				"NO rule: PKIX trust model invisible to the scanner");
	}

	/**
	 * The same ML-KEM that {@code BcPostQuantumDemo} gets detected for, driven through the JDK's
	 * own KEM API instead — and therefore absent from the CBOM.
	 */
	private void jdkKemApi(Evidence evidence) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-KEM", "BC");
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			KEM kem = KEM.getInstance("ML-KEM", "BC");
			KEM.Encapsulator encapsulator = kem.newEncapsulator(keyPair.getPublic());
			KEM.Encapsulated encapsulated = encapsulator.encapsulate();
			evidence.ok("javax.crypto.KEM ML-KEM", encapsulator.providerName(),
					"NO rule: " + encapsulated.encapsulation().length + "-byte encapsulation");
		}
		catch (Exception ex) {
			evidence.unavailable("javax.crypto.KEM ML-KEM", ex.getClass().getSimpleName());
		}
	}

	private KeyPair ecKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
		return keyPairGenerator.generateKeyPair();
	}

	private X509Certificate certificate(String subject, KeyPair subjectKeyPair, KeyPair issuerKeyPair,
			String issuer, boolean ca, boolean serverAuth) throws Exception {
		Instant now = Instant.now();
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				new X500Name(issuer),
				BigInteger.valueOf(now.toEpochMilli()).add(BigInteger.valueOf(Math.abs(subject.hashCode()))),
				Date.from(now.minus(1, ChronoUnit.DAYS)),
				Date.from(now.plus(365, ChronoUnit.DAYS)),
				new X500Name(subject),
				subjectKeyPair.getPublic());

		if (ca) {
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
		}
		else {
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
		}
		if (serverAuth) {
			builder.addExtension(Extension.extendedKeyUsage, false,
					new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
			builder.addExtension(Extension.subjectAlternativeName, false,
					new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
		}

		ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
				.setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.build(issuerKeyPair.getPrivate());
		return new JcaX509CertificateConverter()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.getCertificate(builder.build(signer));
	}

	private void writePem(Path path, X509Certificate certificate) throws Exception {
		String base64 = Base64.getMimeEncoder(64, System.lineSeparator().getBytes())
				.encodeToString(certificate.getEncoded());
		Files.writeString(path, "-----BEGIN CERTIFICATE-----" + System.lineSeparator()
				+ base64 + System.lineSeparator()
				+ "-----END CERTIFICATE-----" + System.lineSeparator());
	}
}
