package com.tinnapat.demo.cbom.jca;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code jca/signature} rules: {@code Signature.getInstance}, {@code setParameter},
 * {@code sign} and {@code verify}.
 *
 * <p>Calling both {@code sign} and {@code verify} matters: those two rules are what populate
 * {@code cryptoProperties.algorithmProperties.cryptoFunctions} with {@code sign} and
 * {@code verify}, rather than leaving the asset with no declared function.
 *
 * <p>{@code ML-DSA} here is a genuine post-quantum signature through the BouncyCastle JCE
 * provider, not a capability string.
 */
public final class JcaSignatureDemo implements CryptoDemo {

	private static final byte[] MESSAGE = "cbom".getBytes();

	@Override
	public String ruleGroup() {
		return "jca/signature";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		ecdsa(evidence, "SHA256withECDSA", "secp256r1");
		ecdsa(evidence, "SHA384withECDSA", "secp384r1");
		rsa(evidence, "SHA256withRSA", 3072);
		rsaPss(evidence);
		edwards(evidence, "Ed25519");
		mlDsa(evidence);

		// --- Deliberately weak: SHA-1 based signatures. ---
		rsa(evidence, "SHA1withRSA", 2048);
	}

	private void ecdsa(Evidence evidence, String algorithm, String curve) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(new ECGenParameterSpec(curve));
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Signature signer = Signature.getInstance(algorithm);
		signer.initSign(keyPair.getPrivate());
		signer.update(MESSAGE);
		byte[] signature = signer.sign();

		Signature verifier = Signature.getInstance(algorithm);
		verifier.initVerify(keyPair.getPublic());
		verifier.update(MESSAGE);
		boolean valid = verifier.verify(signature);
		evidence.ok(algorithm, signer.getProvider().getName(), curve + ", verified=" + valid);
	}

	private void rsa(Evidence evidence, String algorithm, int bits) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(bits);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Signature signer = Signature.getInstance(algorithm);
		signer.initSign(keyPair.getPrivate());
		signer.update(MESSAGE);
		byte[] signature = signer.sign();

		Signature verifier = Signature.getInstance(algorithm);
		verifier.initVerify(keyPair.getPublic());
		verifier.update(MESSAGE);
		boolean valid = verifier.verify(signature);
		evidence.ok(algorithm, signer.getProvider().getName(), "RSA-" + bits + ", verified=" + valid);
	}

	/** {@code setParameter} is a rule of its own, capturing the PSS salt length and MGF digest. */
	private void rsaPss(Evidence evidence) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(3072);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Signature signer = Signature.getInstance("RSASSA-PSS");
		signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
		signer.initSign(keyPair.getPrivate());
		signer.update(MESSAGE);
		byte[] signature = signer.sign();

		Signature verifier = Signature.getInstance("RSASSA-PSS");
		verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
		verifier.initVerify(keyPair.getPublic());
		verifier.update(MESSAGE);
		boolean valid = verifier.verify(signature);
		evidence.ok("RSASSA-PSS", signer.getProvider().getName(), "RSA-3072, MGF1-SHA256, verified=" + valid);
	}

	private void edwards(Evidence evidence, String algorithm) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			Signature signer = Signature.getInstance(algorithm);
			signer.initSign(keyPair.getPrivate());
			signer.update(MESSAGE);
			byte[] signature = signer.sign();

			Signature verifier = Signature.getInstance(algorithm);
			verifier.initVerify(keyPair.getPublic());
			verifier.update(MESSAGE);
			boolean valid = verifier.verify(signature);
			evidence.ok(algorithm, signer.getProvider().getName(), "EdDSA, verified=" + valid);
		}
		catch (Exception ex) {
			evidence.unavailable(algorithm, ex.getClass().getSimpleName());
		}
	}

	/** FIPS 204 post-quantum signature, served by the BouncyCastle JCE provider. */
	private void mlDsa(Evidence evidence) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ML-DSA", "BC");
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			Signature signer = Signature.getInstance("ML-DSA", "BC");
			signer.initSign(keyPair.getPrivate());
			signer.update(MESSAGE);
			byte[] signature = signer.sign();

			Signature verifier = Signature.getInstance("ML-DSA", "BC");
			verifier.initVerify(keyPair.getPublic());
			verifier.update(MESSAGE);
			boolean valid = verifier.verify(signature);
			evidence.ok("ML-DSA", signer.getProvider().getName(), "FIPS 204 post-quantum, verified=" + valid);
		}
		catch (Exception ex) {
			evidence.unavailable("ML-DSA", ex.getClass().getSimpleName());
		}
	}
}
