package com.tinnapat.demo.cbom.bc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSASigner;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets {@code bc/encapsulatedsecret}, {@code bc/signer} (ML-DSA) and {@code bc/messagesigner}
 * (Dilithium).
 *
 * <p>Real post-quantum operations, not a provider capability scan. Each parameter set is a literal
 * constant — {@code MLKEMParameters.ml_kem_768} — so the CBOM records the actual NIST security
 * category rather than just the family name.
 *
 * <p>One scanner gap is deliberately left visible: {@code SLHDSASigner} has no detection rule in
 * the plugin's rule set, while {@code MLDSASigner} and {@code DilithiumSigner} both do. It runs
 * here anyway, so the difference between "the code does it" and "the CBOM says so" is measurable.
 */
public final class BcPostQuantumDemo implements CryptoDemo {

	private static final byte[] MESSAGE = "cbom".getBytes();

	@Override
	public String ruleGroup() {
		return "bc/encapsulatedsecret";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		mlKem(evidence, MLKEMParameters.ml_kem_512, "ml_kem_512");
		mlKem(evidence, MLKEMParameters.ml_kem_768, "ml_kem_768");
		mlKem(evidence, MLKEMParameters.ml_kem_1024, "ml_kem_1024");

		mlDsa(evidence);
		dilithium(evidence);
		slhDsa(evidence);
	}

	/** FIPS 203 key encapsulation: the replacement for the ECDH assets in {@link BcKeyAgreementDemo}. */
	private void mlKem(Evidence evidence, MLKEMParameters parameters, String name) {
		MLKEMKeyPairGenerator keyPairGenerator = new MLKEMKeyPairGenerator();
		keyPairGenerator.init(new MLKEMKeyGenerationParameters(new SecureRandom(), parameters));
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

		MLKEMGenerator generator = new MLKEMGenerator(new SecureRandom());
		SecretWithEncapsulation encapsulated =
				generator.generateEncapsulated((MLKEMPublicKeyParameters) keyPair.getPublic());

		MLKEMExtractor extractor = new MLKEMExtractor((MLKEMPrivateKeyParameters) keyPair.getPrivate());
		byte[] recovered = extractor.extractSecret(encapsulated.getEncapsulation());

		boolean match = java.util.Arrays.equals(encapsulated.getSecret(), recovered);
		evidence.ok("MLKEMGenerator/" + name, "BC light-weight API",
				"FIPS 203, " + encapsulated.getEncapsulation().length + "-byte ciphertext, agreed=" + match);
	}

	/** FIPS 204 lattice signature. */
	private void mlDsa(Evidence evidence) throws Exception {
		MLDSAKeyPairGenerator keyPairGenerator = new MLDSAKeyPairGenerator();
		keyPairGenerator.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65));
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

		MLDSASigner signer = new MLDSASigner();
		signer.init(true, keyPair.getPrivate());
		signer.update(MESSAGE, 0, MESSAGE.length);
		byte[] signature = signer.generateSignature();

		MLDSASigner verifier = new MLDSASigner();
		verifier.init(false, keyPair.getPublic());
		verifier.update(MESSAGE, 0, MESSAGE.length);
		evidence.ok("MLDSASigner/ml_dsa_65", "BC light-weight API",
				"FIPS 204, " + signature.length + "-byte signature, verified=" + verifier.verifySignature(signature));
	}

	/** Pre-standard CRYSTALS-Dilithium, kept because legacy PQC pilots still ship it. */
	private void dilithium(Evidence evidence) throws Exception {
		DilithiumKeyPairGenerator keyPairGenerator = new DilithiumKeyPairGenerator();
		keyPairGenerator.init(new DilithiumKeyGenerationParameters(new SecureRandom(), DilithiumParameters.dilithium3));
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

		DilithiumSigner signer = new DilithiumSigner();
		signer.init(true, keyPair.getPrivate());
		byte[] signature = signer.generateSignature(MESSAGE);

		DilithiumSigner verifier = new DilithiumSigner();
		verifier.init(false, keyPair.getPublic());
		evidence.ok("DilithiumSigner/dilithium3", "BC light-weight API",
				"pre-FIPS draft, verified=" + verifier.verifySignature(MESSAGE, signature));
	}

	/** FIPS 205 hash-based signature. Runs, but no detection rule covers it. */
	private void slhDsa(Evidence evidence) throws Exception {
		SLHDSAKeyPairGenerator keyPairGenerator = new SLHDSAKeyPairGenerator();
		keyPairGenerator.init(new SLHDSAKeyGenerationParameters(new SecureRandom(), SLHDSAParameters.sha2_128s));
		AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

		SLHDSASigner signer = new SLHDSASigner();
		signer.init(true, keyPair.getPrivate());
		byte[] signature = signer.generateSignature(MESSAGE);

		SLHDSASigner verifier = new SLHDSASigner();
		verifier.init(false, keyPair.getPublic());
		boolean valid = verifier.verifySignature(MESSAGE, signature);
		evidence.ok("SLHDSASigner/sha2_128s", "BC light-weight API",
				"FIPS 205, " + signature.length + "-byte signature, verified=" + valid + ", NO detection rule");
	}
}
