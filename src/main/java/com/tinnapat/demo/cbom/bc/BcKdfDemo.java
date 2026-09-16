package com.tinnapat.demo.cbom.bc;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets {@code bc/derivationfunction} and {@code bc/pbe}.
 *
 * <p>Key derivation is a distinct CBOM crypto function from encryption or hashing, and it is
 * routinely missed: a scanner that only greps for algorithm names sees {@code SHA256} here and
 * reports a hash, not an HKDF.
 */
public final class BcKdfDemo implements CryptoDemo {

	private static final byte[] SECRET = "shared-secret".getBytes();
	private static final byte[] SALT = "cbom-demo-salt".getBytes();
	private static final char[] PASSWORD = "cbom-demo-password".toCharArray();

	@Override
	public String ruleGroup() {
		return "bc/derivationfunction";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		hkdf(evidence);
		kdf2(evidence);
		pkcs5S2(evidence);
		pkcs12(evidence);

		// --- Deliberately weak PRF. ---
		hkdfSha1(evidence);
	}

	private void hkdf(Evidence evidence) {
		HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
		generator.init(new HKDFParameters(SECRET, SALT, "cbom-info".getBytes()));
		byte[] output = new byte[32];
		generator.generateBytes(output, 0, output.length);
		evidence.ok("HKDFBytesGenerator(SHA256Digest)", "BC light-weight API", "RFC 5869, 256-bit output");
	}

	private void kdf2(Evidence evidence) {
		KDF2BytesGenerator generator = new KDF2BytesGenerator(new SHA256Digest());
		generator.init(new org.bouncycastle.crypto.params.KDFParameters(SECRET, SALT));
		byte[] output = new byte[32];
		generator.generateBytes(output, 0, output.length);
		evidence.ok("KDF2BytesGenerator(SHA256Digest)", "BC light-weight API", "ANSI X9.63 / IEEE 1363a KDF2");
	}

	private void pkcs5S2(Evidence evidence) {
		PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
		generator.init(PKCS5S2ParametersGenerator.PKCS5PasswordToUTF8Bytes(PASSWORD), SALT, 210_000);
		KeyParameter key = (KeyParameter) generator.generateDerivedParameters(256);
		evidence.ok("PKCS5S2ParametersGenerator(SHA256Digest)", "BC light-weight API",
				"PBKDF2, 210k iterations, " + key.getKey().length * 8 + "-bit key");
	}

	private void pkcs12(Evidence evidence) {
		PKCS12ParametersGenerator generator = new PKCS12ParametersGenerator(new SHA256Digest());
		generator.init(PKCS12ParametersGenerator.PKCS12PasswordToBytes(PASSWORD), SALT, 2_048);
		generator.generateDerivedParameters(256);
		evidence.ok("PKCS12ParametersGenerator(SHA256Digest)", "BC light-weight API",
				"PKCS#12 KDF, 2048 iterations");
	}

	private void hkdfSha1(Evidence evidence) {
		HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA1Digest());
		generator.init(new HKDFParameters(SECRET, SALT, null));
		byte[] output = new byte[20];
		generator.generateBytes(output, 0, output.length);
		evidence.ok("HKDFBytesGenerator(SHA1Digest)", "BC light-weight API", "WEAK: SHA-1 PRF");
	}
}
