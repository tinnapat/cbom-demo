package com.tinnapat.demo.cbom.jca;

import java.security.MessageDigest;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code jca/digest} rule: {@code MessageDigest.getInstance}.
 *
 * <p>Digest assets are where OID accuracy is easiest to check in the generated CBOM, because each
 * SHA-2/SHA-3 variant has its own OID under {@code 2.16.840.1.101.3.4.2}.
 */
public final class JcaDigestDemo implements CryptoDemo {

	private static final byte[] INPUT = "cbom".getBytes();

	@Override
	public String ruleGroup() {
		return "jca/digest";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		digest(evidence, "SHA-256", "SHA-2 family");
		digest(evidence, "SHA-384", "SHA-2 family");
		digest(evidence, "SHA-512", "SHA-2 family");
		digest(evidence, "SHA3-256", "SHA-3 family");
		digest(evidence, "SHA3-512", "SHA-3 family");

		// --- Deliberately broken: collision-vulnerable. ---
		digest(evidence, "SHA-1", "BROKEN: practical collisions");
		digest(evidence, "MD5", "BROKEN: trivial collisions");
	}

	private void digest(Evidence evidence, String algorithm, String note) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
			messageDigest.digest(INPUT);
			evidence.ok(algorithm, messageDigest.getProvider().getName(), note);
		}
		catch (Exception ex) {
			evidence.unavailable(algorithm, ex.getClass().getSimpleName());
		}
	}
}
