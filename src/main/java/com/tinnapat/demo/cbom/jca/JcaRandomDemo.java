package com.tinnapat.demo.cbom.jca;

import java.security.SecureRandom;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code random} rule group.
 *
 * <p>Worth knowing before reading the CBOM: the plugin's three PRNG rules match
 * {@code new SecureRandom(byte[])}, {@code setSeed(byte[])} and {@code setSeed(long)} — they
 * capture the <em>seed size</em>. A bare {@code SecureRandom.getInstance("DRBG")} has no rule, so
 * the algorithm name alone does not become an asset. Both shapes appear below so the gap is
 * visible in the output rather than merely described here.
 */
public final class JcaRandomDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "random";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		byte[] seed = new byte[32];

		// Detected: constructor taking a seed, 256-bit seed material.
		SecureRandom seeded = new SecureRandom(seed);
		seeded.nextInt();
		evidence.ok("SecureRandom(byte[32])", seeded.getProvider().getName(), "256-bit seed, detected by rule");

		// Detected: explicit reseed with byte[].
		SecureRandom strong = SecureRandom.getInstanceStrong();
		strong.setSeed(seed);
		strong.nextInt();
		evidence.ok("SecureRandom.getInstanceStrong", strong.getProvider().getName(), "reseeded with 256-bit seed");

		// Detected as a 64-bit seed: setSeed(long) is a predictable-seed smell.
		SecureRandom weaklySeeded = new SecureRandom();
		weaklySeeded.setSeed(1234567890L);
		weaklySeeded.nextInt();
		evidence.ok("SecureRandom.setSeed(long)", weaklySeeded.getProvider().getName(), "WEAK: 64-bit constant seed");

		// Not detected: no rule matches getInstance on SecureRandom.
		namedPrng(evidence, "DRBG", "NIST SP 800-90A, no detection rule exists");
		namedPrng(evidence, "SHA1PRNG", "WEAK legacy PRNG, no detection rule exists");
	}

	private void namedPrng(Evidence evidence, String algorithm, String note) {
		try {
			SecureRandom random = SecureRandom.getInstance(algorithm);
			random.nextInt();
			evidence.ok("SecureRandom/" + algorithm, random.getProvider().getName(), note);
		}
		catch (Exception ex) {
			evidence.unavailable("SecureRandom/" + algorithm, ex.getClass().getSimpleName());
		}
	}
}
