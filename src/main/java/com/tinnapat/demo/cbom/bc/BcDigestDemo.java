package com.tinnapat.demo.cbom.bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets {@code bc/digest}. The plugin covers 40-plus digest classes; these are the ones a real
 * audit is most likely to meet, plus two broken ones for the compliance view.
 */
public final class BcDigestDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "bc/digest";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		hash(evidence, new SHA256Digest(), "SHA256Digest", "SHA-2 family");
		hash(evidence, new SHA384Digest(), "SHA384Digest", "SHA-2 family");
		hash(evidence, new SHA512Digest(), "SHA512Digest", "SHA-2 family");
		hash(evidence, new SHA3Digest(256), "SHA3Digest(256)", "Keccak permutation, size as a literal");
		hash(evidence, new Blake2bDigest(256), "Blake2bDigest(256)", "not in the NIST catalogue");
		hash(evidence, new SM3Digest(), "SM3Digest", "Chinese national standard");

		// --- Deliberately broken. ---
		hash(evidence, new SHA1Digest(), "SHA1Digest", "BROKEN: practical collisions");
		hash(evidence, new MD5Digest(), "MD5Digest", "BROKEN: trivial collisions");
	}

	private void hash(Evidence evidence, Digest digest, String name, String note) {
		byte[] input = "cbom".getBytes();
		digest.update(input, 0, input.length);
		byte[] out = new byte[digest.getDigestSize()];
		digest.doFinal(out, 0);
		evidence.ok(name, "BC light-weight API", out.length * 8 + "-bit output: " + note);
	}
}
