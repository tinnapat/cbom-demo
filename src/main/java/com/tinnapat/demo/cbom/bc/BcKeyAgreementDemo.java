package com.tinnapat.demo.cbom.bc;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets {@code bc/basicagreement}.
 *
 * <p>These are the classical key-exchange primitives that a post-quantum migration has to replace,
 * so pairing this class with {@link BcPostQuantumDemo} in one CBOM is what makes the migration
 * story legible: same repository, ECDH assets next to ML-KEM assets.
 */
public final class BcKeyAgreementDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "bc/basicagreement";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		ecdh(evidence, new ECDHBasicAgreement(), "ECDHBasicAgreement", "secp256r1");
		ecdh(evidence, new ECDHCBasicAgreement(), "ECDHCBasicAgreement", "secp384r1");
		finiteFieldDh(evidence);
	}

	private void ecdh(Evidence evidence, BasicAgreement agreement, String name, String curve) {
		AsymmetricCipherKeyPair local = ecKeyPair(curve);
		AsymmetricCipherKeyPair remote = ecKeyPair(curve);
		agreement.init(local.getPrivate());
		BigInteger secret = agreement.calculateAgreement(remote.getPublic());
		evidence.ok(name, "BC light-weight API", curve + ", " + secret.bitLength() + "-bit shared secret");
	}

	private void finiteFieldDh(Evidence evidence) {
		// RFC 3526 MODP group 14 (2048-bit), used so the demo stays fast and deterministic.
		BigInteger p = new BigInteger(
				"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
						+ "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
						+ "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
						+ "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
						+ "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
						+ "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
						+ "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
						+ "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);
		DHParameters parameters = new DHParameters(p, BigInteger.TWO);

		DHBasicKeyPairGenerator generator = new DHBasicKeyPairGenerator();
		generator.init(new DHKeyGenerationParameters(new SecureRandom(), parameters));
		AsymmetricCipherKeyPair local = generator.generateKeyPair();
		AsymmetricCipherKeyPair remote = generator.generateKeyPair();

		BasicAgreement agreement = new DHBasicAgreement();
		agreement.init(local.getPrivate());
		BigInteger secret = agreement.calculateAgreement(remote.getPublic());
		evidence.ok("DHBasicAgreement", "BC light-weight API",
				"2048-bit MODP group 14, " + secret.bitLength() + "-bit shared secret");
	}

	private AsymmetricCipherKeyPair ecKeyPair(String curve) {
		X9ECParameters x9 = ECNamedCurveTable.getByName(curve);
		ECDomainParameters domain = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
		ECKeyPairGenerator generator = new ECKeyPairGenerator();
		generator.init(new ECKeyGenerationParameters(domain, new SecureRandom()));
		return generator.generateKeyPair();
	}
}
