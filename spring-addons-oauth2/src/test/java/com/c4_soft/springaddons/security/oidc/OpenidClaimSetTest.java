package com.c4_soft.springaddons.security.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.jayway.jsonpath.PathNotFoundException;

class OpenidClaimSetTest {

  @Test
  void givenUsernameClaimIsPresent_whenGetName_thenItsValue() {
    final var claims = new OpenidClaimSet(
        Map.of("sub", "1234", "preferred_username", "ch4mp"), "preferred_username");

    assertThat(claims.getName()).isEqualTo("ch4mp");
  }

  @Test
  void givenUsernameClaimIsANestedJsonPath_whenGetName_thenItsValue() {
    final var claims = new OpenidClaimSet(
        Map.of("sub", "1234", "user", Map.of("login", "ch4mp")), "$.user.login");

    assertThat(claims.getName()).isEqualTo("ch4mp");
  }

  @Test
  void givenUsernameClaimIsMissing_whenGetName_thenSub() {
    final var claims = new OpenidClaimSet(Map.of("sub", "1234"), "preferred_username");

    assertThat(claims.getName()).isEqualTo("1234");
  }

  @Test
  void givenUsernameClaimIsNotAString_whenGetName_thenItsStringValue() {
    final var claims = new OpenidClaimSet(Map.of("sub", 1234L, "uid", 42), "uid");

    assertThat(claims.getName()).isEqualTo("42");
    assertThat(new OpenidClaimSet(Map.of("sub", 1234L)).getName()).isEqualTo("1234");
  }

  @Test
  void givenNeitherUsernameClaimNorSub_whenGetName_thenPathNotFound() {
    final var claims = new OpenidClaimSet(Map.of("iss", "https://op"), "preferred_username");

    assertThatThrownBy(claims::getName).isInstanceOf(PathNotFoundException.class);
  }
}
