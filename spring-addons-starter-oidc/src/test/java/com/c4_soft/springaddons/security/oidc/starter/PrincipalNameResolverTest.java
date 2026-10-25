package com.c4_soft.springaddons.security.oidc.starter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import com.jayway.jsonpath.PathNotFoundException;

/**
 * The name read from the claims by the default authentication converters (issue #319): the
 * configured username claim, else {@code sub}, else an {@link InvalidBearerTokenException}
 * ({@code 401}) rather than the {@link PathNotFoundException} of {@code OpenidClaimSet}
 * ({@code 500}).
 */
class PrincipalNameResolverTest {
  private static final String USERNAME_CLAIM = "$.preferred_username";

  @Test
  void givenUsernameClaimIsPresent_thenItIsTheName() {
    assertThat(PrincipalNameResolver
        .principalName(Map.of("sub", "123", "preferred_username", "ch4mp"), USERNAME_CLAIM))
        .isEqualTo("ch4mp");
  }

  @Test
  void givenUsernameClaimIsAbsent_thenSubIsTheName() {
    assertThat(PrincipalNameResolver.principalName(Map.of("sub", "123"), USERNAME_CLAIM))
        .isEqualTo("123");
  }

  @Test
  void givenNumericSub_thenNameIsItsString() {
    assertThat(PrincipalNameResolver.principalName(Map.of("sub", 123), "sub")).isEqualTo("123");
  }

  @Test
  void givenNeitherUsernameClaimNorSub_thenInvalidBearerTokenExceptionWithoutThePath() {
    assertThatThrownBy(
        () -> PrincipalNameResolver.principalName(Map.of("iss", "x"), USERNAME_CLAIM))
        .isInstanceOfSatisfying(InvalidBearerTokenException.class,
            e -> assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN))
        .hasMessageNotContaining("preferred_username")
        .hasCauseInstanceOf(PathNotFoundException.class);
  }

  @Test
  void givenNullSub_thenInvalidBearerTokenException() {
    final var claims = new HashMap<String, Object>(Map.of("iss", "x"));
    claims.put("sub", null);

    assertThatThrownBy(() -> PrincipalNameResolver.principalName(claims, "sub"))
        .isInstanceOf(InvalidBearerTokenException.class);
  }
}
