package com.tinnapat.demo.cbom.jca;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;

import javax.crypto.KeyAgreement;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code jca/keyagreement} rules ({@code getInstance}, {@code init},
 * {@code generateSecret}) and {@code jca/algorithmparametergenerator}.
 *
 * <p>Key exchange is the category most often missing from a CBOM, and the reason is usually that
 * the project talks about ECDHE in comments or config strings instead of calling
 * {@code KeyAgreement}. A scanner can only report what the code actually does, so every entry
 * below completes a real two-party agreement.
 */
public final class JcaKeyAgreementDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "jca/keyagreement";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		ecdh(evidence, "secp256r1");
		ecdh(evidence, "secp384r1");
		xdh(evidence, "X25519");
		xdh(evidence, "X448");
		finiteFieldDh(evidence);
		dhParameterGeneration(evidence);
	}

	private void ecdh(Evidence evidence, String curve) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		keyPairGenerator.initialize(new ECGenParameterSpec(curve));
		KeyPair local = keyPairGenerator.generateKeyPair();
		KeyPair remote = keyPairGenerator.generateKeyPair();

		KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
		keyAgreement.init(local.getPrivate());
		keyAgreement.doPhase(remote.getPublic(), true);
		byte[] secret = keyAgreement.generateSecret();
		evidence.ok("ECDH", keyAgreement.getProvider().getName(), curve + ", " + secret.length * 8 + "-bit secret");
	}

	private void xdh(Evidence evidence, String curve) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("XDH");
			keyPairGenerator.initialize(new NamedParameterSpec(curve));
			KeyPair local = keyPairGenerator.generateKeyPair();
			KeyPair remote = keyPairGenerator.generateKeyPair();

			KeyAgreement keyAgreement = KeyAgreement.getInstance("XDH");
			keyAgreement.init(local.getPrivate());
			keyAgreement.doPhase(remote.getPublic(), true);
			byte[] secret = keyAgreement.generateSecret();
			evidence.ok("XDH/" + curve, keyAgreement.getProvider().getName(), secret.length * 8 + "-bit secret");
		}
		catch (Exception ex) {
			evidence.unavailable("XDH/" + curve, ex.getClass().getSimpleName());
		}
	}

	private void finiteFieldDh(Evidence evidence) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DiffieHellman");
		keyPairGenerator.initialize(2048);
		KeyPair local = keyPairGenerator.generateKeyPair();
		KeyPair remote = keyPairGenerator.generateKeyPair();

		KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
		keyAgreement.init(local.getPrivate());
		keyAgreement.doPhase(remote.getPublic(), true);
		byte[] secret = keyAgreement.generateSecret();
		evidence.ok("DiffieHellman", keyAgreement.getProvider().getName(), "2048-bit group, " + secret.length * 8 + "-bit secret");
	}

	/**
	 * {@code jca/algorithmparametergenerator} is its own rule group: generating a DH group is a
	 * distinct crypto function from agreeing a key with it, and the bit size is a literal the
	 * scanner can attach to the asset.
	 */
	private void dhParameterGeneration(Evidence evidence) throws Exception {
		AlgorithmParameterGenerator generator = AlgorithmParameterGenerator.getInstance("DH");
		generator.init(2048);
		AlgorithmParameters parameters = generator.generateParameters();
		evidence.ok("DH parameters", generator.getProvider().getName(),
				"freshly generated 2048-bit group (" + parameters.getAlgorithm() + ")");
	}
}
