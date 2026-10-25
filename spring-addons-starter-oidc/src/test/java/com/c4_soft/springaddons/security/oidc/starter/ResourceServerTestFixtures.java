package com.c4_soft.springaddons.security.oidc.starter;

import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

/**
 * Tokens and properties for the resource server tests, servlet and reactive
 */
public final class ResourceServerTestFixtures {
  private ResourceServerTestFixtures() {}

  public static final String ISSUER = "https://localhost:8443/realms/test";

  /** The single OpenID Provider of the test contexts */
  public static final String ISSUER_PROPERTY = "com.c4-soft.springaddons.oidc.ops[0].iss=" + ISSUER;

  /** Its username claim: the configured JSON path must never reach the client */
  public static final String USERNAME_CLAIM_PROPERTY =
      "com.c4-soft.springaddons.oidc.ops[0].username-claim=preferred_username";

  /** {@code /public} needs no authentication */
  public static final String PERMIT_ALL_PUBLIC_PROPERTY =
      "com.c4-soft.springaddons.oidc.resourceserver.permit-all=/public";

  /** Switches the resource server to token introspection (an introspector bean is needed too) */
  public static final String INTROSPECTION_URI_PROPERTY =
      "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=" + ISSUER
          + "/protocol/openid-connect/token/introspect";

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
