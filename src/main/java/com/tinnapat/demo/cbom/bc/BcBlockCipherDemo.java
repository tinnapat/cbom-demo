package com.tinnapat.demo.cbom.bc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets {@code bc/blockcipher}, {@code bc/bufferedblockcipher} and
 * {@code bc/blockcipherpadding}.
 *
 * <p>Each usage composes three separately detected pieces — engine, mode and padding — which the
 * plugin's translation step reassembles into a single algorithm asset. The legacy engines at the
 * bottom exist so the CBOM has genuinely non-compliant block ciphers to report.
 */
public final class BcBlockCipherDemo implements CryptoDemo {

	private static final byte[] MESSAGE = "cbom-block-cipher-demo".getBytes();

	@Override
	public String ruleGroup() {
		return "bc/blockcipher";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		SecureRandom random = new SecureRandom();
		byte[] key256 = new byte[32];
		byte[] iv16 = new byte[16];
		random.nextBytes(key256);
		random.nextBytes(iv16);

		aesCbcPkcs7(evidence, key256, iv16);
		aesCtr(evidence, key256, iv16);

		// --- Deliberately legacy engines with 64-bit blocks. ---
		tripleDesCbc(evidence);
		desCbc(evidence);
		blowfishCbc(evidence);
	}

	private void aesCbcPkcs7(Evidence evidence, byte[] key, byte[] iv) throws Exception {
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				CBCBlockCipher.newInstance(AESEngine.newInstance()), new PKCS7Padding());
		cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
		process(cipher);
		evidence.ok("AES/CBC/PKCS7 (light-weight)", "BC light-weight API", "AES-256, explicit padding object");
	}

	private void aesCtr(Evidence evidence, byte[] key, byte[] iv) throws Exception {
		BufferedBlockCipher cipher = new DefaultBufferedBlockCipher(
				SICBlockCipher.newInstance(AESEngine.newInstance()));
		cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
		process(cipher);
		evidence.ok("AES/CTR (light-weight)", "BC light-weight API", "AES-256, SIC/CTR mode, no padding");
	}

	private void tripleDesCbc(Evidence evidence) throws Exception {
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				CBCBlockCipher.newInstance(new DESedeEngine()), new PKCS7Padding());
		cipher.init(true, new ParametersWithIV(new KeyParameter(new byte[24]), new byte[8]));
		process(cipher);
		evidence.ok("DESede/CBC/PKCS7 (light-weight)", "BC light-weight API", "WEAK: 112-bit effective, 64-bit block");
	}

	private void desCbc(Evidence evidence) throws Exception {
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				CBCBlockCipher.newInstance(new DESEngine()), new PKCS7Padding());
		cipher.init(true, new ParametersWithIV(new KeyParameter(new byte[8]), new byte[8]));
		process(cipher);
		evidence.ok("DES/CBC/PKCS7 (light-weight)", "BC light-weight API", "BROKEN: 56-bit key");
	}

	private void blowfishCbc(Evidence evidence) throws Exception {
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
				CBCBlockCipher.newInstance(new BlowfishEngine()), new PKCS7Padding());
		cipher.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[8]));
		process(cipher);
		evidence.ok("Blowfish/CBC/PKCS7 (light-weight)", "BC light-weight API", "WEAK: 64-bit block, sweet32");
	}

	private void process(BufferedBlockCipher cipher) throws Exception {
		byte[] out = new byte[cipher.getOutputSize(MESSAGE.length)];
		int written = cipher.processBytes(MESSAGE, 0, MESSAGE.length, out, 0);
		cipher.doFinal(out, written);
	}
}
