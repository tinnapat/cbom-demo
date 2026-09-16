package com.tinnapat.demo.cbom.bc;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets {@code bc/signer} and {@code bc/dsa}.
 *
 * <p>{@code new DSADigestSigner(new ECDSASigner(), new SHA256Digest())} is the light-weight
 * equivalent of the JCA string {@code "SHA256withECDSA"} — but as two composed types, so the
 * signature algorithm and its digest arrive as separate, individually verifiable facts.
 */
public final class BcSignerDemo implements CryptoDemo {

	private static final byte[] MESSAGE = "cbom".getBytes();

	@Override
	public String ruleGroup() {
		return "bc/signer";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		ecdsaSha256(evidence);
		rsaSha256(evidence);
		rsaPss(evidence);
		ed25519(evidence);

		// --- Deliberately weak digest inside an otherwise fine signature scheme. ---
		rsaSha1(evidence);
	}

	private void ecdsaSha256(Evidence evidence) throws Exception {
		AsymmetricCipherKeyPair keyPair = ecKeyPair("secp256r1");
		Signer signer = new DSADigestSigner(new ECDSASigner(), new SHA256Digest());
		signer.init(true, keyPair.getPrivate());
		signer.update(MESSAGE, 0, MESSAGE.length);
		byte[] signature = signer.generateSignature();

		Signer verifier = new DSADigestSigner(new ECDSASigner(), new SHA256Digest());
		verifier.init(false, keyPair.getPublic());
		verifier.update(MESSAGE, 0, MESSAGE.length);
		evidence.ok("DSADigestSigner(ECDSASigner, SHA256Digest)", "BC light-weight API",
				"secp256r1, verified=" + verifier.verifySignature(signature));
	}

	private void rsaSha256(Evidence evidence) throws Exception {
		AsymmetricCipherKeyPair keyPair = rsaKeyPair(3072);
		Signer signer = new RSADigestSigner(new SHA256Digest());
		signer.init(true, keyPair.getPrivate());
		signer.update(MESSAGE, 0, MESSAGE.length);
		byte[] signature = signer.generateSignature();

		Signer verifier = new RSADigestSigner(new SHA256Digest());
		verifier.init(false, keyPair.getPublic());
		verifier.update(MESSAGE, 0, MESSAGE.length);
		evidence.ok("RSADigestSigner(SHA256Digest)", "BC light-weight API",
				"RSA-3072 PKCS#1 v1.5, verified=" + verifier.verifySignature(signature));
	}

	private void rsaPss(Evidence evidence) throws Exception {
		AsymmetricCipherKeyPair keyPair = rsaKeyPair(3072);
		Signer signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
		signer.init(true, keyPair.getPrivate());
		signer.update(MESSAGE, 0, MESSAGE.length);
		byte[] signature = signer.generateSignature();

		Signer verifier = new PSSSigner(new RSAEngine(), new SHA256Digest(), 32);
		verifier.init(false, keyPair.getPublic());
		verifier.update(MESSAGE, 0, MESSAGE.length);
		evidence.ok("PSSSigner(RSAEngine, SHA256Digest, 32)", "BC light-weight API",
				"RSA-3072 PSS, 32-byte salt, verified=" + verifier.verifySignature(signature));
	}

	private void ed25519(Evidence evidence) throws Exception {
		Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
		generator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
		AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

		Signer signer = new Ed25519Signer();
		signer.init(true, keyPair.getPrivate());
		signer.update(MESSAGE, 0, MESSAGE.length);
		byte[] signature = signer.generateSignature();

		Signer verifier = new Ed25519Signer();
		verifier.init(false, keyPair.getPublic());
		verifier.update(MESSAGE, 0, MESSAGE.length);
		evidence.ok("Ed25519Signer", "BC light-weight API",
				"EdDSA over Curve25519, verified=" + verifier.verifySignature(signature));
	}

	private void rsaSha1(Evidence evidence) throws Exception {
		AsymmetricCipherKeyPair keyPair = rsaKeyPair(2048);
		Signer signer = new RSADigestSigner(new SHA1Digest());
		signer.init(true, keyPair.getPrivate());
		signer.update(MESSAGE, 0, MESSAGE.length);
		signer.generateSignature();
		evidence.ok("RSADigestSigner(SHA1Digest)", "BC light-weight API", "WEAK: SHA-1 digest");
	}

	private AsymmetricCipherKeyPair ecKeyPair(String curve) {
		X9ECParameters x9 = ECNamedCurveTable.getByName(curve);
		ECDomainParameters domain = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
		ECKeyPairGenerator generator = new ECKeyPairGenerator();
		generator.init(new ECKeyGenerationParameters(domain, new SecureRandom()));
		return generator.generateKeyPair();
	}

	private AsymmetricCipherKeyPair rsaKeyPair(int bits) {
		RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
		generator.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), bits, 80));
		return generator.generateKeyPair();
	}
}
