# Builds a runnable image of the demo so the CBOM story can be told at the container layer too.
#
# A container CBOM answers questions the source scan cannot: which algorithms the JRE's
# java.security policy actually disables, what OpenSSL's config permits, and which certificates
# ship in the trust store. Note that openssl itself appears as an OS *package* in the SBOM, not as
# a cryptographic-asset — it is the provider of crypto, not an instance of it.

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q package -DskipTests \
	# Generates target/demo-pki so the certificates and keystore are baked into the image
	# and cbomkit-theia's certificate/keys plugins have something to find.
	&& mvn -B -q exec:java

FROM eclipse-temurin:21-jre
# openssl is installed explicitly so /etc/ssl/openssl.cnf exists and the package is unambiguously
# present in the image SBOM; ca-certificates brings the system trust store.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends openssl ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /build/target/cbom-demo-*.jar /app/cbom-demo.jar
COPY --from=build /build/target/libs /app/libs
# Demo-only PKI: throwaway keys generated during the build, never committed to the repository.
COPY --from=build /build/target/demo-pki /app/demo-pki

ENTRYPOINT ["java", "-jar", "/app/cbom-demo.jar"]
