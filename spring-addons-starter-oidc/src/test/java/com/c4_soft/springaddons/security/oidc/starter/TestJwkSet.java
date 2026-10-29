package com.c4_soft.springaddons.security.oidc.starter;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

/**
 * An RSA key pair, its public JWK set served over HTTP by the JDK's own server on a free port, and
 * a signer for test tokens.
 */
public class TestJwkSet implements AutoCloseable {

  private final RSAKey key;
  private final HttpServer server;
  private final URI jwkSetUri;

  public TestJwkSet() throws Exception {
    key = new RSAKeyGenerator(2048).keyID("test-key").keyUse(KeyUse.SIGNATURE)
        .algorithm(JWSAlgorithm.RS256).generate();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.start();
    jwkSetUri = serveJson("/jwks", new JWKSet(key.toPublicJWK()).toString());
  }

  public URI jwkSetUri() {
    return jwkSetUri;
  }

  /**
   * @param path where to serve the JSON body (a token endpoint, for instance)
   * @param json the body of every response
   * @return the URI of the endpoint
   */
  public URI serveJson(String path, String json) {
    final var body = json.getBytes(StandardCharsets.UTF_8);
    server.createContext(path, exchange -> {
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, body.length);
      try (var out = exchange.getResponseBody()) {
        out.write(body);
      }
    });
    return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
  }

  /**
   * @param typ the {@code typ} JOSE header, or null for none
   * @param claims the claim-set
   * @return a token signed with the private key
   */
  public String sign(@Nullable String typ, JWTClaimsSet claims) throws JOSEException {
    final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID());
    if (typ != null) {
      header.type(new JOSEObjectType(typ));
    }
    final var jwt = new SignedJWT(header.build(), claims);
    jwt.sign(new RSASSASigner(key));
    return jwt.serialize();
  }

  /**
   * @return a claim-set valid for five minutes, with the given issuer and audience
   */
  public static JWTClaimsSet claims(String issuer, String audience) {
    return claims(issuer, audience, Map.of());
  }

  /**
   * @return a claim-set valid for five minutes, with the given issuer, audience and other claims
   */
  public static JWTClaimsSet claims(String issuer, String audience, Map<String, ?> otherClaims) {
    final var now = Instant.now();
    final var builder = new JWTClaimsSet.Builder().issuer(issuer).subject("ch4mp")
        .audience(List.of(audience)).issueTime(Date.from(now))
        .expirationTime(Date.from(now.plusSeconds(300)));
    otherClaims.forEach(builder::claim);
    return builder.build();
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
