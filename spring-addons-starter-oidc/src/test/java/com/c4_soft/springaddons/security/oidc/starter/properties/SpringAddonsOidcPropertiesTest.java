package com.c4_soft.springaddons.security.oidc.starter.properties;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;

class SpringAddonsOidcPropertiesTest {

  @Test
  void givenNoOpenidProvider_whenGetUsernameClaimForIntrospectionUri_thenSub() {
    final var properties = new SpringAddonsOidcProperties();

    assertThat(properties.getUsernameClaimForIntrospectionUri("https://op/introspect"))
        .isEqualTo("sub");
  }

  @Test
  void givenOpenidProviderIssuerIsInIntrospectionUri_whenGetUsernameClaimForIntrospectionUri_thenItsUsernameClaim() {
    final var properties = new SpringAddonsOidcProperties();
    properties.setOps(List.of(op(URI.create("https://other"), "email"),
        op(URI.create("https://op/realm"), "preferred_username")));

    assertThat(properties.getUsernameClaimForIntrospectionUri("https://op/realm/introspect"))
        .isEqualTo("preferred_username");
  }

  @Test
  void givenNoOpenidProviderIssuerMatchesIntrospectionUri_whenGetUsernameClaimForIntrospectionUri_thenFirstOpenidProviderUsernameClaim() {
    final var properties = new SpringAddonsOidcProperties();
    properties.setOps(List.of(op(null, "email"), op(URI.create("https://op/realm"), "name")));

    assertThat(properties.getUsernameClaimForIntrospectionUri("https://elsewhere/introspect"))
        .isEqualTo("email");
    assertThat(properties.getUsernameClaimForIntrospectionUri(null)).isEqualTo("email");
  }

  private static OpenidProviderProperties op(URI iss, String usernameClaim) {
    final var op = new OpenidProviderProperties();
    op.setIss(iss);
    op.setUsernameClaim(usernameClaim);
    return op;
  }
}
