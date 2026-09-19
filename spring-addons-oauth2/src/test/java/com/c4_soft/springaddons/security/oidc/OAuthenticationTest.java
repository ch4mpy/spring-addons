package com.c4_soft.springaddons.security.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class OAuthenticationTest {

  @Test
  void whenConstructed_thenAuthenticated() {
    assertThat(authentication().isAuthenticated()).isTrue();
  }

  @Test
  void whenSetAuthenticatedFalse_thenNoLongerTrusted() {
    final var auth = authentication();

    auth.setAuthenticated(false);

    assertThat(auth.isAuthenticated()).isFalse();
  }

  @Test
  void whenSetAuthenticatedTrue_thenIllegalArgument() {
    assertThatThrownBy(() -> authentication().setAuthenticated(true))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static OAuthentication<OpenidToken> authentication() {
    return new OAuthentication<>(new OpenidToken(Map.of("sub", "ch4mp"), "sub", "a.b.c"),
        List.of());
  }
}
