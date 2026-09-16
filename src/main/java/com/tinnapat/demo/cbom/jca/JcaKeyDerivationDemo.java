package com.tinnapat.demo.cbom.jca;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code jca/keyfactory} rules for {@code SecretKeyFactory} plus the
 * {@code PBEKeySpec}, {@code DESKeySpec} and {@code DESedeKeySpec} key-spec rules.
 *
 * <p>{@code PBEKeySpec} is the interesting one: the iteration count and key length are literals in
 * the constructor, so a scanner can put both into the derived asset and a policy can then judge
 * whether the KDF is strong enough.
 */
public final class JcaKeyDerivationDemo implements CryptoDemo {

	private static final char[] PASSWORD = "cbom-demo-password".toCharArray();
	private static final byte[] SALT = "cbom-demo-salt-16".getBytes();

	@Override
	public String ruleGroup() {
		return "jca/keyfactory";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		pbkdf2(evidence, "PBKDF2WithHmacSHA256", 210_000, 256, "OWASP 2023 iteration guidance");
		pbkdf2(evidence, "PBKDF2WithHmacSHA512", 210_000, 512, "SHA-512 based PBKDF2");

		// --- Deliberately weak: SHA-1 PRF and an iteration count far below any current guidance. ---
		pbkdf2(evidence, "PBKDF2WithHmacSHA1", 1_000, 160, "WEAK: SHA-1 PRF, 1k iterations");

		legacyKeySpecs(evidence);
	}

	private void pbkdf2(Evidence evidence, String algorithm, int iterations, int keyBits, String note) {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
			factory.generateSecret(new PBEKeySpec(PASSWORD, SALT, iterations, keyBits));
			evidence.ok(algorithm, factory.getProvider().getName(), iterations + " iterations, " + keyBits + "-bit output: " + note);
		}
		catch (Exception ex) {
			evidence.unavailable(algorithm, ex.getClass().getSimpleName());
		}
	}

	/** DESKeySpec and DESedeKeySpec each have their own detection rule. */
	private void legacyKeySpecs(Evidence evidence) {
		try {
			SecretKeyFactory desede = SecretKeyFactory.getInstance("DESede");
			desede.generateSecret(new DESedeKeySpec("24-byte-key-for-3des-demo".getBytes()));
			evidence.ok("DESede key spec", desede.getProvider().getName(), "WEAK: 112-bit effective");
		}
		catch (Exception ex) {
			evidence.unavailable("DESede key spec", ex.getClass().getSimpleName());
		}
		try {
			SecretKeyFactory des = SecretKeyFactory.getInstance("DES");
			des.generateSecret(new DESKeySpec("8-bytes!".getBytes()));
			evidence.ok("DES key spec", des.getProvider().getName(), "BROKEN: 56-bit key");
		}
		catch (Exception ex) {
			evidence.unavailable("DES key spec", ex.getClass().getSimpleName());
		}
	}
}
