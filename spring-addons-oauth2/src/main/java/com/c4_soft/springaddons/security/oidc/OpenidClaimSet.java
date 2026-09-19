package com.c4_soft.springaddons.security.oidc;

import java.security.Principal;
import java.util.Map;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import com.jayway.jsonpath.PathNotFoundException;
import lombok.Getter;

public class OpenidClaimSet extends UnmodifiableClaimSet
    implements IdTokenClaimAccessor, Principal {
  private static final long serialVersionUID = -5149299350697429528L;

  /**
   * JSON path for the claim to use as "name" source
   */
  @Getter
  private final String usernameClaim;

  public OpenidClaimSet(Map<String, Object> claims, String usernameClaim) {
    super(claims);
    this.usernameClaim = usernameClaim;
  }

  public OpenidClaimSet(Map<String, Object> claims) {
    this(claims, StandardClaimNames.SUB);
  }

  @Override
  public Map<String, Object> getClaims() {
    return this;
  }

  /**
   * @return the value at the username claim JSON path, or the {@code sub} claim if there is none,
   *         as a string (numeric identifiers are common)
   * @throws PathNotFoundException if neither the username claim nor {@code sub} is present
   */
  @Override
  public String getName() {
    Object name;
    try {
      name = getByJsonPath(usernameClaim);
    } catch (PathNotFoundException e) {
      name = getByJsonPath(JwtClaimNames.SUB);
    }
    return name == null ? null : name.toString();
  }

}
