package com.c4_soft.springaddons.security.oidc.starter;

import java.util.Map;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.jayway.jsonpath.PathNotFoundException;

/**
 * Reads the principal name of a bearer token for the starter's default authentication converters
 * (internal to the starter: not part of its public API). A token with neither the username claim
 * nor {@code sub} is refused with an {@link InvalidBearerTokenException}, an
 * {@code AuthenticationException} which the bearer token filters hand to the authentication entry
 * point ({@code 401}), instead of letting the {@link PathNotFoundException} of
 * {@link OpenidClaimSet#getName()} escape the security filter-chain as a {@code 500} (issue #319).
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class PrincipalNameResolver {
  private PrincipalNameResolver() {}

  // a fixed text: the configured username claim (a JSON path) is not echoed to the client
  private static final String ERROR_DESCRIPTION =
      "The token has neither the username claim nor a sub claim";

  /**
   * @param claims the claims of a decoded JWT, or the attributes of an introspected token
   * @param usernameClaim the JSON path of the username claim ({@code sub} is used when it is
   *        absent)
   * @return the value at the username claim, or else the {@code sub} claim, as a string
   * @throws InvalidBearerTokenException if neither the username claim nor {@code sub} is present,
   *         or if the one found is {@code null}
   */
  public static String principalName(Map<String, Object> claims, String usernameClaim) {
    final String name;
    try {
      name = new OpenidClaimSet(claims, usernameClaim).getName();
    } catch (PathNotFoundException e) {
      throw new InvalidBearerTokenException(ERROR_DESCRIPTION, e);
    }
    if (name == null) {
      throw new InvalidBearerTokenException(ERROR_DESCRIPTION);
    }
    return name;
  }
}
