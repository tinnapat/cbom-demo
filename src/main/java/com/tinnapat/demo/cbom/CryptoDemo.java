package com.tinnapat.demo.cbom;

/**
 * One group of cryptographic asset usages that a CBOM scanner should be able to detect.
 *
 * <p>Every implementation exercises real crypto APIs with literal algorithm names at the call site,
 * because that is what an AST-based scanner such as the PQCA Sonar Cryptography plugin captures.
 * Nothing here models crypto with strings or maps: if an asset is claimed, the API call exists.
 */
public interface CryptoDemo {

	/** Rule group this demo targets, e.g. {@code jca/cipher} or {@code bc/aeadcipher}. */
	String ruleGroup();

	/** Runs every usage in the group, reporting what actually executed at runtime. */
	void run(Evidence evidence) throws Exception;
}
