package com.tinnapat.demo.cbom.jca;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code jca/cipher} rules: {@code Cipher.getInstance}, {@code Cipher.init} and
 * {@code Cipher.wrap}.
 *
 * <p>The transformation string carries primitive, mode and padding in one literal, which is how a
 * scanner recovers {@code cryptoProperties.algorithmProperties.mode} and {@code padding}. The
 * deliberately weak entries at the bottom give the quantum-safety and compliance views something
 * to flag.
 */
public final class JcaCipherDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "jca/cipher";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		SecureRandom random = new SecureRandom();

		aesGcm(evidence, random);
		aesCbc(evidence, random);
		aesCtr(evidence, random);
		chaCha20Poly1305(evidence, random);
		aesKeyWrap(evidence);
		rsaOaep(evidence);

		// --- Deliberately weak or legacy: expected to show up as non-compliant assets. ---
		aesEcb(evidence);
		tripleDes(evidence, random);
		singleDes(evidence, random);
		rsaPkcs1(evidence);
	}

	private void aesGcm(Evidence evidence, SecureRandom random) throws Exception {
		SecretKey key = aesKey(256);
		byte[] nonce = new byte[12];
		random.nextBytes(nonce);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
		cipher.doFinal("cbom".getBytes());
		evidence.ok("AES/GCM/NoPadding", cipher.getProvider().getName(), "AES-256, 128-bit tag");
	}

	private void aesCbc(Evidence evidence, SecureRandom random) throws Exception {
		SecretKey key = aesKey(256);
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		cipher.doFinal("cbom".getBytes());
		evidence.ok("AES/CBC/PKCS5Padding", cipher.getProvider().getName(), "AES-256, unauthenticated");
	}

	private void aesCtr(Evidence evidence, SecureRandom random) throws Exception {
		SecretKey key = aesKey(128);
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		cipher.doFinal("cbom".getBytes());
		evidence.ok("AES/CTR/NoPadding", cipher.getProvider().getName(), "AES-128 stream mode");
	}

	private void chaCha20Poly1305(Evidence evidence, SecureRandom random) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("ChaCha20");
			SecretKey key = keyGenerator.generateKey();
			byte[] nonce = new byte[12];
			random.nextBytes(nonce);
			Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
			cipher.doFinal("cbom".getBytes());
			evidence.ok("ChaCha20-Poly1305", cipher.getProvider().getName(), "256-bit key, AEAD");
		}
		catch (Exception ex) {
			evidence.unavailable("ChaCha20-Poly1305", ex.getClass().getSimpleName());
		}
	}

	/** Covers the separate {@code Cipher.wrap} rule, which yields a keyWrap crypto function. */
	private void aesKeyWrap(Evidence evidence) throws Exception {
		SecretKey wrappingKey = aesKey(256);
		SecretKey target = aesKey(128);
		Cipher cipher = Cipher.getInstance("AESWrap");
		cipher.init(Cipher.WRAP_MODE, wrappingKey);
		cipher.wrap(target);
		evidence.ok("AESWrap", cipher.getProvider().getName(), "RFC 3394 key wrapping");
	}

	private void rsaOaep(Evidence evidence) throws Exception {
		KeyPair keyPair = rsaKeyPair(3072);
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		cipher.doFinal("cbom".getBytes());
		evidence.ok("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", cipher.getProvider().getName(), "RSA-3072");
	}

	private void aesEcb(Evidence evidence) throws Exception {
		SecretKey key = aesKey(128);
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipher.doFinal("cbom".getBytes());
		evidence.ok("AES/ECB/PKCS5Padding", cipher.getProvider().getName(), "WEAK: ECB leaks plaintext structure");
	}

	private void tripleDes(Evidence evidence, SecureRandom random) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
			SecretKey key = keyGenerator.generateKey();
			byte[] iv = new byte[8];
			random.nextBytes(iv);
			Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			cipher.doFinal("cbom".getBytes());
			evidence.ok("DESede/CBC/PKCS5Padding", cipher.getProvider().getName(), "WEAK: 112-bit effective");
		}
		catch (Exception ex) {
			evidence.unavailable("DESede/CBC/PKCS5Padding", ex.getClass().getSimpleName());
		}
	}

	private void singleDes(Evidence evidence, SecureRandom random) {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
			SecretKey key = keyGenerator.generateKey();
			byte[] iv = new byte[8];
			random.nextBytes(iv);
			Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			cipher.doFinal("cbom".getBytes());
			evidence.ok("DES/CBC/PKCS5Padding", cipher.getProvider().getName(), "BROKEN: 56-bit key");
		}
		catch (Exception ex) {
			evidence.unavailable("DES/CBC/PKCS5Padding", ex.getClass().getSimpleName());
		}
	}

	private void rsaPkcs1(Evidence evidence) throws Exception {
		KeyPair keyPair = rsaKeyPair(2048);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		cipher.doFinal("cbom".getBytes());
		evidence.ok("RSA/ECB/PKCS1Padding", cipher.getProvider().getName(), "WEAK: PKCS#1 v1.5 padding");
	}

	private SecretKey aesKey(int bits) throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(bits);
		return keyGenerator.generateKey();
	}

	private KeyPair rsaKeyPair(int bits) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(bits);
		return keyPairGenerator.generateKeyPair();
	}
}
