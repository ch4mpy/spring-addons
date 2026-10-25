package com.c4_soft.springaddons.security.oidc.starter;

import java.util.Map;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.jayway.jsonpath.PathNotFoundException;

/**
 * Reads the principal name of a bearer token, for the default authentication converters of
 * resource servers. A token with neither the username claim nor {@code sub} is refused with an
 * {@link InvalidBearerTokenException}: an {@code AuthenticationException}, which the bearer token
 * filters hand to the authentication entry point ({@code 401}) instead of letting a {@code 500}
 * escape the security filter-chain (issue #319).
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class PrincipalNameResolver {
  private PrincipalNameResolver() {}

  /**
   * @param claims the claims of a decoded JWT, or the attributes of an introspected token
   * @param usernameClaim the JSON path of the username claim ({@code sub} is used when it is
   *        absent)
   * @return the value at the username claim, or else the {@code sub} claim, as a string
   * @throws InvalidBearerTokenException if neither the username claim nor {@code sub} is present
   */
  public static String principalName(Map<String, Object> claims, String usernameClaim) {
    try {
      return new OpenidClaimSet(claims, usernameClaim).getName();
    } catch (PathNotFoundException e) {
      throw new InvalidBearerTokenException(
          "Neither the username claim (%s) nor sub is present in the token claims"
              .formatted(usernameClaim),
          e);
    }
  }
}
