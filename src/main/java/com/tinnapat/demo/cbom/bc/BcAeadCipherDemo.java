package com.tinnapat.demo.cbom.bc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMSIVBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code bc/aeadcipher} rules.
 *
 * <p>This is where the light-weight API beats a JCA transformation string. {@code
 * GCMBlockCipher.newInstance(AESEngine.newInstance())} names the mode and the block cipher engine
 * as two separate types, so the scanner emits AES as the primitive with GCM as its mode and the
 * tag length taken from {@code AEADParameters} — no string parsing involved.
 */
public final class BcAeadCipherDemo implements CryptoDemo {

	private static final byte[] MESSAGE = "cbom".getBytes();

	@Override
	public String ruleGroup() {
		return "bc/aeadcipher";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		SecureRandom random = new SecureRandom();
		byte[] key = new byte[32];
		byte[] nonce = new byte[12];
		random.nextBytes(key);
		random.nextBytes(nonce);

		aesGcm(evidence, key, nonce);
		aesCcm(evidence, key, nonce);
		aesGcmSiv(evidence, key, nonce);
		chaCha20Poly1305(evidence, key, nonce);
	}

	private void aesGcm(Evidence evidence, byte[] key, byte[] nonce) throws Exception {
		AEADCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
		cipher.init(true, new AEADParameters(new KeyParameter(key), 128, nonce));
		process(cipher);
		evidence.ok("AES/GCM (light-weight)", "BC light-weight API", "AES-256, 128-bit tag");
	}

	private void aesCcm(Evidence evidence, byte[] key, byte[] nonce) throws Exception {
		AEADCipher cipher = CCMBlockCipher.newInstance(AESEngine.newInstance());
		cipher.init(true, new AEADParameters(new KeyParameter(key), 128, nonce));
		process(cipher);
		evidence.ok("AES/CCM (light-weight)", "BC light-weight API", "AES-256, 128-bit tag");
	}

	private void aesGcmSiv(Evidence evidence, byte[] key, byte[] nonce) throws Exception {
		GCMSIVBlockCipher cipher = new GCMSIVBlockCipher(AESEngine.newInstance());
		cipher.init(true, new AEADParameters(new KeyParameter(key), 128, nonce));
		process(cipher);
		evidence.ok("AES/GCM-SIV (light-weight)", "BC light-weight API", "AES-256, nonce-misuse resistant");
	}

	private void chaCha20Poly1305(Evidence evidence, byte[] key, byte[] nonce) throws Exception {
		ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
		cipher.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
		process(cipher);
		evidence.ok("ChaCha20-Poly1305 (light-weight)", "BC light-weight API", "256-bit key, RFC 8439");
	}

	private void process(AEADCipher cipher) throws Exception {
		byte[] out = new byte[cipher.getOutputSize(MESSAGE.length)];
		int written = cipher.processBytes(MESSAGE, 0, MESSAGE.length, out, 0);
		cipher.doFinal(out, written);
	}
}
