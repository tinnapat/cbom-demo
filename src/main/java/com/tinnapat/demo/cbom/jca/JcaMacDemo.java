package com.tinnapat.demo.cbom.jca;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code jca/mac} rule ({@code Mac.getInstance}) plus the {@code SecretKeySpec} key
 * rule, which is what lets a scanner attach a key length to the MAC asset.
 */
public final class JcaMacDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "jca/mac";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		generatedKeyMac(evidence, "HmacSHA256", "HMAC over SHA-256");
		generatedKeyMac(evidence, "HmacSHA512", "HMAC over SHA-512");
		generatedKeyMac(evidence, "HmacSHA3-256", "HMAC over SHA3-256");

		// SecretKeySpec makes the 256-bit key material explicit in the source.
		byte[] raw = new byte[32];
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(raw, "HmacSHA256"));
		mac.doFinal("cbom".getBytes());
		evidence.ok("HmacSHA256", mac.getProvider().getName(), "explicit 256-bit SecretKeySpec");

		// --- Deliberately weak underlying digests. ---
		generatedKeyMac(evidence, "HmacSHA1", "WEAK: SHA-1 based");
		generatedKeyMac(evidence, "HmacMD5", "WEAK: MD5 based");
	}

	private void generatedKeyMac(Evidence evidence, String algorithm, String note) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
			SecretKey key = keyGenerator.generateKey();
			Mac mac = Mac.getInstance(algorithm);
			mac.init(key);
			mac.doFinal("cbom".getBytes());
			evidence.ok(algorithm, mac.getProvider().getName(), note);
		}
		catch (Exception ex) {
			evidence.unavailable(algorithm, ex.getClass().getSimpleName());
		}
	}
}
