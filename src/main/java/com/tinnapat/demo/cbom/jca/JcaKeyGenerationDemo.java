package com.tinnapat.demo.cbom.jca;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets {@code jca/keygenerator} ({@code KeyGenerator} and {@code KeyPairGenerator}, both
 * {@code getInstance} and the {@code init}/{@code initialize} rules that carry the key size) and
 * {@code jca/keyfactory} for {@code KeyFactory}.
 *
 * <p>The {@code init(bits)} call is what gives an asset its {@code classicalSecurityLevel}. An
 * {@code AES} asset with no key size attached cannot be judged against a policy, which is exactly
 * the weakness of keyword-based scanners.
 */
public final class JcaKeyGenerationDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "jca/keygenerator";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		symmetric(evidence, "AES", 256);
		symmetric(evidence, "AES", 128);
		symmetric(evidence, "ChaCha20", 256);
		symmetric(evidence, "HmacSHA256", 256);

		asymmetric(evidence, "RSA", 4096);
		asymmetric(evidence, "RSA", 3072);
		namedCurve(evidence, "secp521r1");
		postQuantum(evidence, "ML-KEM");
		postQuantum(evidence, "ML-DSA");

		keyFactoryRoundTrip(evidence);

		// --- Deliberately weak key sizes. ---
		asymmetric(evidence, "RSA", 1024);
		namedCurve(evidence, "secp192r1");
	}

	private void symmetric(Evidence evidence, String algorithm, int bits) throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
		keyGenerator.init(bits);
		keyGenerator.generateKey();
		evidence.ok(algorithm + "-" + bits, keyGenerator.getProvider().getName(), "symmetric key generation");
	}

	private void asymmetric(Evidence evidence, String algorithm, int bits) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
		keyPairGenerator.initialize(bits);
		keyPairGenerator.generateKeyPair();
		String note = bits < 2048 ? "WEAK: below 2048-bit minimum" : "classical asymmetric key";
		evidence.ok(algorithm + "-" + bits, keyPairGenerator.getProvider().getName(), note);
	}

	private void namedCurve(Evidence evidence, String curve) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
			keyPairGenerator.initialize(new ECGenParameterSpec(curve));
			keyPairGenerator.generateKeyPair();
			evidence.ok("EC/" + curve, keyPairGenerator.getProvider().getName(), "named curve via ECGenParameterSpec");
		}
		catch (Exception ex) {
			evidence.unavailable("EC/" + curve, ex.getClass().getSimpleName());
		}
	}

	private void postQuantum(Evidence evidence, String algorithm) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			evidence.ok(algorithm, keyPairGenerator.getProvider().getName(),
					"post-quantum, public key " + keyPair.getPublic().getEncoded().length + " bytes");
		}
		catch (Exception ex) {
			evidence.unavailable(algorithm, ex.getClass().getSimpleName());
		}
	}

	/** {@code KeyFactory.generatePublic} is its own rule, distinct from {@code getInstance}. */
	private void keyFactoryRoundTrip(Evidence evidence) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PublicKey decoded = keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublic().getEncoded()));
		evidence.ok("EC key factory", keyFactory.getProvider().getName(), "X.509 SubjectPublicKeyInfo decode, " + decoded.getFormat());
	}
}
