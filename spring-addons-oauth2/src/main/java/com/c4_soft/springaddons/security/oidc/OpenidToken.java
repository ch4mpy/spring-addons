package com.c4_soft.springaddons.security.oidc;

import java.time.Instant;
import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2Token;

public class OpenidToken extends OpenidClaimSet implements OAuth2Token {
  private static final long serialVersionUID = 913910545139553602L;

  private final String tokenValue;

  public OpenidToken(Map<String, Object> claims, String usernameClaim, String tokenValue) {
    super(claims, usernameClaim);
    this.tokenValue = tokenValue;
  }

  public OpenidToken(OpenidClaimSet openidClaimSet, String tokenValue) {
    super(openidClaimSet, openidClaimSet.getUsernameClaim());
    this.tokenValue = tokenValue;
  }

  @Override
  public String getTokenValue() {
    return tokenValue;
  }

  @Override
  public Instant getExpiresAt() {
    return super.getExpiresAt();
  }

  @Override
  public Instant getIssuedAt() {
    return super.getIssuedAt();
  }

}
