# CBOM Scanner Demo

A deliberately crypto-dense Java project whose only purpose is to show **what CBOM scanners can and cannot detect**.

The code exists to be scanned. Every algorithm claim in this repository is backed by a real API call with a literal algorithm name at the call site — nothing is modelled with strings, config or comments — because a scanner can only report what the code actually does.

## Result

Three source scanners, same repository, one build:

| Scanner | How it works | Assets | With source location | With mode | With crypto functions |
| --- | --- | --- | --- | --- | --- |
| [PQCA sonar-cryptography](https://github.com/PQCA/sonar-cryptography) | AST + type resolution | **213** | 213 | 20 | 69 |
| [cdxgen](https://github.com/cdxgen/cdxgen) `--include-crypto` | keyword → OID mapping | 10 | 0 | 0 | 0 |
| [cbomkit-theia](https://github.com/cbomkit/cbomkit-theia) | filesystem inspection | 13 | 13 | 0 | 8 |

`sonar-cryptography` finds ~21x more than `cdxgen` on the same Java code. The reason is structural, not a tuning difference — see [Why the gap](#why-the-gap).

Two further vantage points that no source scan provides:

| Vantage point | What it adds |
| --- | --- |
| [container image](#the-container-layer) | 224 OS packages including `openssl` 3.5.5 and `libssl3t64`, plus **8 947** crypto assets — 1 454 of them certificates from the system trust store |
| [runtime](#runtime-evidence) | **110 algorithm usages actually executed**, each with the provider that served it and the JVM's refusals |

Every number on this page is read out of the scans committed in [out/](out/) — nothing is transcribed by hand. `./scripts/compare.sh` recomputes the comparison table from those files, and `python3 scripts/report.py` writes a full asset-to-source map from them, so you can check any claim here against the JSON that produced it.

## Quick start

Requires Docker, JDK 21+, Maven, Node (for cdxgen) and Go (for theia).

```sh
git clone https://github.com/tinnapat/cbom-demo.git && cd cbom-demo

./scripts/sonarqube-up.sh     # build the plugin, start SonarQube, activate the CBOM rule
./scripts/scan-cbom.sh        # the real CBOM            -> out/cbom-sonar.json
./scripts/scan-cdxgen.sh      # keyword baseline         -> out/cbom-cdxgen.json
./scripts/scan-theia.sh       # certificates and keys    -> out/cbom-theia.json
./scripts/scan-image.sh       # container layer          -> out/{sbom,cbom}-image.json
mvn -q exec:java              # runtime evidence         -> target/runtime-evidence.md
./scripts/compare.sh          # the table above, from the actual files
python3 scripts/report.py     # writes docs/RESULTS.md + docs/cbom-source-map.md
```

`sonarqube-up.sh` takes a few minutes the first time: it builds the plugin from source and waits for SonarQube to boot. Everything after that is seconds to a couple of minutes.

The five BOM files in `out/` are committed, so the comparison can be read — and diffed against your own run — without installing anything. What the scanners produce alongside them (logs, the exported image tar, cdxgen's atom slices) is swept into `out/work/`, which is gitignored.

Teardown: `docker compose down -v`.

## Why the gap

**cdxgen's crypto detection is not built for Java.** Its `--include-crypto` does real constant propagation for JavaScript/TypeScript and calls `dosai` for .NET; for Java it maps algorithm keywords to OIDs. That has three consequences visible in `out/cbom-cdxgen.json`:

- **No source locations.** All 10 assets have empty `evidence`, so you cannot tell where anything is used.
- **No parameters.** `aes` appears once, with OID `2.16.840.1.101.3.4.1` — the AES *arc*, not AES-256-GCM (`…3.4.1.46`). Key size, mode and padding are all absent, so no policy can judge it.
- **Imprecise names and OIDs.** The four distinct HMACs in this code (`HmacSHA1`, `HmacSHA256`, `HmacSHA512`, `HmacSHA3-256`) collapse into one asset called `hmacSHA`, carrying `1.3.6.1.5.5.8.1.2` — an OID that means HMAC-SHA1 specifically. Its `sha-1` OID `2.16.840.1.113719.1.2.8.82` is a vendor arc rather than the standard `1.3.14.3.2.26`.

Whole categories are missed: every post-quantum algorithm, every key agreement, every KDF, all TLS protocol versions, and the digests SHA-384, SHA3-512, SM3, BLAKE2b and cSHAKE.

**sonar-cryptography walks the AST with types resolved**, so `GCMBlockCipher.newInstance(AESEngine.newInstance())` becomes one asset with `primitive: ae`, `mode: gcm` and the tag length from `AEADParameters` — three composed types reassembled into one fact, which is exactly what keyword matching cannot do. This is also why [`scripts/scan-cbom.sh`](scripts/scan-cbom.sh) builds the project first and passes `sonar.java.binaries`: without compiled classes the analyzer cannot resolve BouncyCastle symbols and most detections silently vanish.

Sample asset from `out/cbom-sonar.json`:

```json
{
  "type": "cryptographic-asset",
  "name": "AES-GCM",
  "evidence": { "occurrences": [ {
    "location": "src/main/java/com/tinnapat/demo/cbom/bc/BcAeadCipherDemo.java",
    "line": 50, "offset": 49,
    "additionalContext": "org.bouncycastle.crypto.engines.AESEngine#newInstance()..."
  } ] },
  "cryptoProperties": {
    "assetType": "algorithm",
    "algorithmProperties": { "primitive": "ae", "parameterSetIdentifier": "128", "mode": "gcm" },
    "oid": "2.16.840.1.101.3.4.1"
  }
}
```

## What the code covers

Each class targets a named rule group in the plugin and is documented with what that group can capture.

| Package | Classes | Rule groups |
| --- | --- | --- |
| [jca/](src/main/java/com/tinnapat/demo/cbom/jca/) | cipher, digest, mac, signature, key agreement, key derivation, key generation, PRNG | `jca/cipher`, `jca/digest`, `jca/mac`, `jca/signature`, `jca/keyagreement`, `jca/keyfactory`, `jca/keygenerator`, `jca/algorithmparametergenerator`, `random` |
| [tls/](src/main/java/com/tinnapat/demo/cbom/tls/) | `TlsConfigurationDemo` | `ssl` |
| [bc/](src/main/java/com/tinnapat/demo/cbom/bc/) | AEAD, block cipher, digest, MAC, signer, KDF, key agreement, post-quantum | `bc/aeadcipher`, `bc/blockcipher`, `bc/blockcipherpadding`, `bc/digest`, `bc/mac`, `bc/signer`, `bc/dsa`, `bc/derivationfunction`, `bc/pbe`, `bc/basicagreement`, `bc/encapsulatedsecret` |
| [gaps/](src/main/java/com/tinnapat/demo/cbom/gaps/) | `ScannerGapDemo` | *(none — that is the point)* |

The 87 distinct algorithm assets include full composites (`AES-128-CBC-PKCS5`, `DESede-CBC-PKCS7`), correct signature OIDs (`ECDSA-SHA-256` → `1.2.840.10045.4.3.2`), real post-quantum assets (`ML-KEM-768` → `2.16.840.1.101.3.4.4.2`, `ML-DSA-65` → `…3.4.3.18`), four TLS protocol assets, and 122 `related-crypto-material` entries (84 secret keys, 16 salts, 15 passwords, 6 initialization vectors, 1 public key).

### Deliberately weak entries

Roughly a quarter of the usages are broken or deprecated on purpose — MD5, SHA-1, single DES, 3DES, Blowfish, AES-ECB, RSA-1024, RSA PKCS#1 v1.5, PBKDF2 at 1 000 iterations with a SHA-1 PRF, TLS 1.1, `setSeed(long)` with a constant. Without them a compliance or quantum-readiness view has nothing to flag and the demo looks artificially clean.

## Where each tool stops

This is the part worth demoing: no single scanner is sufficient.

**Not detected by sonar-cryptography** — all present in [`ScannerGapDemo`](src/main/java/com/tinnapat/demo/cbom/gaps/ScannerGapDemo.java) and all confirmed absent from `out/cbom-sonar.json`:

| Usage | Why there is no rule |
| --- | --- |
| `CertificateFactory`, `KeyStore` | no JCA rules exist for either |
| `KeyManagerFactory`, `TrustManagerFactory` | the PKIX trust model is invisible |
| `JcaX509v3CertificateBuilder`, `JcaContentSignerBuilder` | BouncyCastle *JCA bridge*; the plugin covers only the light-weight API |
| `javax.crypto.KEM` (JDK 21+) | no rule — so ML-KEM used this way disappears, even though the same algorithm **is** detected via the light-weight API |
| `SecureRandom.getInstance("DRBG")` | the PRNG rules match `new SecureRandom(byte[])` and `setSeed(…)`, capturing seed size, not the algorithm name |

**cbomkit-theia covers the filesystem half** that a source scanner structurally cannot: it reads the certificates and PKCS#12 keystore that `ScannerGapDemo` writes to `target/demo-pki/`, producing 2 `certificate` assets and a `pkcs12-file` entry. Run `mvn exec:java` before `scan-theia.sh` or there is nothing on disk to find. Note that theia scans the whole directory tree, so [`scripts/scan-theia.sh`](scripts/scan-theia.sh) keeps its own checkout outside the repo — otherwise theia's test fixtures show up as this project's certificates and leaked secrets.

**Measured limits of the AST scanner itself**, useful to state plainly rather than oversell:

- `nistQuantumSecurityLevel` is populated on none of the 87 algorithm assets, so post-quantum classification still needs a policy layer such as [CBOMkit](https://github.com/cbomkit/cbomkit).
- Only 48 of 213 assets carry an OID; 20 carry a mode.
- `DilithiumSigner`, `SLHDSASigner`, `SM2Signer`, `Ed448Signer` and `GMac` run in this project but produce no asset; `MLKEMParameters.ml_kem_512` / `ml_kem_1024` collapse into a single `ML-KEM-768` entry; and `ECGenParameterSpec("secp192r1")` yields no curve asset even though `secp256r1`, `secp384r1` and `secp521r1` all do.
- `JcaRandomDemo` contributes zero occurrences despite three matching call shapes.

## The container layer

`./scripts/scan-image.sh` builds [Dockerfile](Dockerfile) and scans the image. This is a fourth vantage point, and it answers questions none of the source-level scans can.

**OS packages that provide crypto** — from cdxgen, out of 224 library components in the image:

| Package | Version |
| --- | --- |
| `openssl` / `openssl-provider-legacy` | 3.5.5-1ubuntu3.5 |
| `libssl3t64` | 3.5.5-1ubuntu3.5 |
| `gnutls28` / `libgnutls30t64` | 3.8.12-2ubuntu1.1 |
| `libgcrypt20` | 1.12.0-2ubuntu1.1 |
| `nettle` / `libnettle8t64` | 3.10.2-1 |
| `libk5crypto3` | 1.22.1-2ubuntu4.1 |
| `p11-kit` / `p11-kit-modules` / `libp11-kit0` | 0.26.2-2 |
| `ca-certificates` | 20260601~26.04.1 |

Note the classification: **openssl is an operating-system package, not a `cryptographic-asset`.** A CBOM's crypto assets are algorithms, certificates, protocols and key material; openssl is the library that provides them. Both belong in a container inventory, in different sections — and a "CBOM" that lists openssl as a crypto asset has conflated the two.

**Crypto assets inside the image** — from cbomkit-theia, 8 947 assets, dominated by things that simply do not exist at source level:

| Asset type | Count | Where it comes from |
| --- | --- | --- |
| certificate | 1 454 | the system trust store, plus the 2 demo certificates baked into `/app/demo-pki` |
| algorithm | 5 903 | signature and key algorithms of every certificate, plus the merged source CBOM |
| related-crypto-material | 1 586 | public keys from the trust store, and key material found in the filesystem |
| protocol | 4 | the TLS assets carried over from the source CBOM |

theia also locates `/etc/ssl/openssl.cnf` (and its `/lib/ssl` and `/usr/lib/ssl` aliases) and reads `/opt/java/openjdk/conf/security/java.security`.

**Chaining the source CBOM into the image scan** is the interesting experiment, and the honest result is a partial one. Passing `--bom out/cbom-sonar.json` is required for theia's `javasecurity` plugin to run at all — without it the plugin disables itself. With it, the plugin loads the JRE policy and marks all 213 source assets as in scope, but produces **no verdicts**: its actual check compares TLS cipher suites against `jdk.tls.disabledAlgorithms`, and the source CBOM's protocol assets carry no `cipherSuites`, so all four fail with `component has not enough information (cipherSuites)`. Nothing in the merged output changes.

That is worth demoing precisely because it shows what the tool would need. "Is AES-128-CBC-PKCS5 actually permitted in this container?" is the right question, and today no single tool in this repository answers it.

Two build notes worth knowing if you adapt this: cdxgen is handed `docker save` output rather than the image name, because a containerd-based runtime installed alongside Docker (k3s, Rancher Desktop) makes cdxgen pick the wrong socket and fail to find the image. And theia skips any file over 1 MiB, so the BouncyCastle jars in `/app/libs` are never inspected — its findings are filesystem-level, not archive-level.

## Runtime evidence

`target/runtime-evidence.md` lists each algorithm the JVM actually ran and the provider that served it — SunJCE, SunEC, BC, or a refusal. A static CBOM says what the code can do; this says what the platform permitted. Reading them together is how you separate a scanner blind spot from a runtime restriction.

## Layout

```
src/main/java/com/tinnapat/demo/cbom/
  CbomDemoRunner.java     entry point; runs every group, writes runtime evidence
  CryptoDemo.java         one interface per rule group
  Evidence.java           runtime evidence collector
  jca/ tls/ bc/ gaps/     the asset corpus
scripts/
  sonarqube-up.sh         plugin build + SonarQube + CBOM rule activation
  scan-cbom.sh            the real CBOM
  scan-cdxgen.sh          keyword baseline
  scan-theia.sh           certificates, keys, java.security
  scan-image.sh           OS packages and the container's crypto assets
  compare.sh              the comparison table
  report.py               writes the recorded numbers and the asset-to-source map into docs/
Dockerfile                runnable image, with the demo PKI baked in at build time
docker-compose.yml        SonarQube + Postgres with the crypto plugin mounted
out/                      the CBOM and SBOM files, committed so they can be read as examples
  work/                   logs, the exported image tar, cdxgen's atom slices (gitignored)
target/demo-pki/          generated demo certificates and keystore (gitignored)
```

## Notes on the demo material

All keys, certificates and the PKCS#12 keystore are generated at runtime into `target/demo-pki/` and are gitignored. Nothing secret is committed. The keystore password is the literal string `cbom-demo-not-a-secret`, and it protects a throwaway generated key.

The plugin is built from source because it is published only to GitHub Packages, which needs authentication; `sonarqube-up.sh` handles that and skips `spotless`, whose pinned formatter rejects newer JVMs.

## Also worth trying

- **[CBOMkit](https://github.com/cbomkit/cbomkit)** (`make production`) — the full platform: same detection engine plus a UI, compliance policies and post-quantum scoring. It does not build the repository before scanning, which costs accuracy on Java.
- **[cbomkit-action](https://github.com/cbomkit/cbomkit-action)** — the same scan in CI. Build first: `mvn -B clean package -DskipTests`, then `CBOMKIT_LANGUAGES: java`.
- **JVM-level tracing** — `-Djava.security.debug=provider,engine=Cipher,engine=Signature` and `-Djavax.net.debug=ssl,handshake` show algorithm resolution inside dependencies, which no source scan of this repository can reach.
