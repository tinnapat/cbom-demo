package com.tinnapat.demo.cbom.bc;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.KeyParameter;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets {@code bc/mac}.
 *
 * <p>{@code CMac} and {@code GMac} are the interesting cases: both are MACs built from a block
 * cipher, so the scanner has to follow the nested {@code AESEngine} to know the MAC is AES-based.
 * That nesting is exactly what a keyword scanner cannot do.
 */
public final class BcMacDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "bc/mac";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		hmacSha256(evidence);
		cmacAes(evidence);
		gmacAes(evidence);
		kmac(evidence);

		// --- Deliberately weak underlying digest. ---
		hmacMd5(evidence);
	}

	private void hmacSha256(Evidence evidence) {
		Mac mac = new HMac(new SHA256Digest());
		mac.init(new KeyParameter(new byte[32]));
		evidence.ok("HMac(SHA256Digest)", "BC light-weight API", finish(mac) + "-bit tag");
	}

	private void cmacAes(Evidence evidence) {
		Mac mac = new CMac(AESEngine.newInstance());
		mac.init(new KeyParameter(new byte[32]));
		evidence.ok("CMac(AESEngine)", "BC light-weight API", finish(mac) + "-bit tag, AES-based MAC");
	}

	private void gmacAes(Evidence evidence) {
		Mac mac = new GMac(GCMBlockCipher.newInstance(AESEngine.newInstance()));
		mac.init(new ParametersWithIV(new KeyParameter(new byte[32]), new byte[12]));
		evidence.ok("GMac(GCMBlockCipher(AESEngine))", "BC light-weight API", finish(mac) + "-bit tag, GHASH based");
	}

	private void kmac(Evidence evidence) {
		Mac mac = new KMAC(256, new byte[0]);
		mac.init(new KeyParameter(new byte[32]));
		evidence.ok("KMAC(256)", "BC light-weight API", finish(mac) + "-bit tag, SHA-3 based");
	}

	private void hmacMd5(Evidence evidence) {
		Mac mac = new HMac(new MD5Digest());
		mac.init(new KeyParameter(new byte[16]));
		evidence.ok("HMac(MD5Digest)", "BC light-weight API", "WEAK: MD5 based, " + finish(mac) + "-bit tag");
	}

	private int finish(Mac mac) {
		byte[] input = "cbom".getBytes();
		mac.update(input, 0, input.length);
		byte[] out = new byte[mac.getMacSize()];
		mac.doFinal(out, 0);
		return out.length * 8;
	}
}
