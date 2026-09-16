package com.tinnapat.demo.cbom.tls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import com.tinnapat.demo.cbom.CryptoDemo;
import com.tinnapat.demo.cbom.Evidence;

/**
 * Targets the {@code ssl} rule group: {@code SSLContext.getInstance},
 * {@code SSLParameters.setProtocols}, and the {@code SSLServerSocket} methods
 * {@code setEnabledProtocols}, {@code setEnabledCipherSuites} and {@code setSSLParameters}.
 *
 * <p>These rules are why TLS becomes a protocol asset in the CBOM instead of a comment. Note that
 * the socket rules use exact-type matching on {@code javax.net.ssl.SSLServerSocket}, so the
 * variable below is deliberately declared as that type rather than {@code ServerSocket}.
 */
public final class TlsConfigurationDemo implements CryptoDemo {

	@Override
	public String ruleGroup() {
		return "ssl";
	}

	@Override
	public void run(Evidence evidence) throws Exception {
		sslContext(evidence, "TLSv1.3");
		sslContext(evidence, "TLSv1.2");
		// Unversioned, as a great deal of real code is written. The resulting asset has no
		// version, and merges with the TLS node the plugin derives from the cipher-suite
		// detections below -- visible as one TLS asset with several source lines.
		sslContext(evidence, "TLS");

		// --- Deliberately obsolete protocol version. ---
		sslContext(evidence, "TLSv1.1");

		sslParameters(evidence);
		serverSocket(evidence);
		legacyServerSocket(evidence);
	}

	private void sslContext(Evidence evidence, String protocol) {
		try {
			SSLContext sslContext = SSLContext.getInstance(protocol);
			sslContext.init(null, null, null);
			String note = protocol.startsWith("TLSv1.1") ? "WEAK: deprecated protocol version" : "protocol asset";
			evidence.ok("SSLContext/" + protocol, sslContext.getProvider().getName(), note);
		}
		catch (Exception ex) {
			evidence.unavailable("SSLContext/" + protocol, ex.getClass().getSimpleName());
		}
	}

	private void sslParameters(Evidence evidence) {
		SSLParameters parameters = new SSLParameters();
		parameters.setProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
		parameters.setCipherSuites(new String[] { "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256" });
		evidence.ok("SSLParameters", "JSSE", "protocols " + String.join(",", parameters.getProtocols()));
	}

	/**
	 * Binds an ephemeral port purely so the configuration calls are real. The socket is closed
	 * immediately; nothing is served.
	 */
	/**
	 * A TLS 1.2 socket, whose cipher suite names carry key exchange and authentication as well as
	 * the cipher and hash — far more for a scanner to decompose than a TLS 1.3 suite.
	 */
	private void legacyServerSocket(Evidence evidence) {
		SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(0)) {
			serverSocket.setEnabledProtocols(new String[] { "TLSv1.2" });
			serverSocket.setEnabledCipherSuites(new String[] {
					"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" });
			evidence.ok("SSLServerSocket TLSv1.2", "JSSE",
					"ECDHE key exchange, RSA and ECDSA authentication");
		}
		catch (Exception ex) {
			evidence.unavailable("SSLServerSocket TLSv1.2", ex.getClass().getSimpleName());
		}
	}

	private void serverSocket(Evidence evidence) {
		SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(0)) {
			serverSocket.setEnabledProtocols(new String[] { "TLSv1.3" });
			// Several suites in one call: the plugin builds a CipherSuite node per string, and
			// whether they reach protocolProperties.cipherSuites is what this demo measures.
			serverSocket.setEnabledCipherSuites(new String[] {
					"TLS_AES_256_GCM_SHA384",
					"TLS_AES_128_GCM_SHA256",
					"TLS_CHACHA20_POLY1305_SHA256" });

			SSLParameters parameters = new SSLParameters();
			parameters.setProtocols(new String[] { "TLSv1.3" });
			parameters.setNeedClientAuth(true);
			serverSocket.setSSLParameters(parameters);

			evidence.ok("SSLServerSocket", "JSSE",
					"TLSv1.3 only, mTLS required, port " + serverSocket.getLocalPort());
		}
		catch (Exception ex) {
			evidence.unavailable("SSLServerSocket", ex.getClass().getSimpleName());
		}
	}
}
