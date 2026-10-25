package com.c4_soft.springaddons.security.oidc.starter;

import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

/**
 * Tokens for the resource server tests, servlet and reactive
 */
public final class ResourceServerTestFixtures {
  private ResourceServerTestFixtures() {}

  public static final String ISSUER = "https://localhost:8443/realms/test";

  /** A decoded JWT, as a mocked decoder returns it */
  public static Jwt jwt(Map<String, Object> claims) {
    return Jwt.withTokenValue("test").header("alg", "none").claims(c -> c.putAll(claims)).build();
  }

  /** A successful introspection result, as a mocked introspector returns it */
  public static OAuth2IntrospectionAuthenticatedPrincipal introspectionPrincipal(
      Map<String, Object> attributes) {
    return new OAuth2IntrospectionAuthenticatedPrincipal(attributes, List.of());
  }

  /**
   * A serialized unsigned JWT with {@code issuer} as only claim: the authentication manager
   * resolvers parse the bearer string to read its issuer before the decoder runs
   */
  public static String plainJwt(String issuer) {
    return new PlainJWT(new JWTClaimsSet.Builder().issuer(issuer).build()).serialize();
  }
}
