package com.c4_soft.springaddons.security.oidc.starter.properties;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
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

  @Test
  void givenNoTypProperty_whenBind_thenJwtAndAtJwt() {
    final var properties = bind(Map.of("com.c4-soft.springaddons.oidc.ops[0].iss", "https://op"));

    assertThat(properties.getOps().get(0).getTyp()).containsExactly("jwt", "at+jwt");
  }

  @Test
  void givenCommaSeparatedTypProperty_whenBind_thenList() {
    final var properties = bind(Map.of("com.c4-soft.springaddons.oidc.ops[0].iss", "https://op",
        "com.c4-soft.springaddons.oidc.ops[0].typ", "jwt,at+jwt"));

    assertThat(properties.getOps().get(0).getTyp()).containsExactly("jwt", "at+jwt");
  }

  @Test
  void givenIndexedTypProperty_whenBind_thenList() {
    final var properties = bind(Map.of("com.c4-soft.springaddons.oidc.ops[0].iss", "https://op",
        "com.c4-soft.springaddons.oidc.ops[0].typ[0]", "at+jwt",
        "com.c4-soft.springaddons.oidc.ops[0].typ[1]", "application/at+jwt"));

    assertThat(properties.getOps().get(0).getTyp()).containsExactly("at+jwt",
        "application/at+jwt");
  }

  @Test
  void givenNoAuthorizedPartiesProperty_whenBind_thenEmpty() {
    final var properties = bind(Map.of("com.c4-soft.springaddons.oidc.ops[0].iss", "https://op"));

    assertThat(properties.getOps().get(0).getAuthorizedParties()).isEmpty();
  }

  @Test
  void givenCommaSeparatedAuthorizedPartiesProperty_whenBind_thenList() {
    final var properties = bind(Map.of("com.c4-soft.springaddons.oidc.ops[0].iss", "https://op",
        "com.c4-soft.springaddons.oidc.ops[0].authorized-parties", "gateway, bruno"));

    assertThat(properties.getOps().get(0).getAuthorizedParties()).containsExactly("gateway",
        "bruno");
  }

  @Test
  void givenIndexedAuthorizedPartiesProperty_whenBind_thenList() {
    final var properties = bind(Map.of("com.c4-soft.springaddons.oidc.ops[0].iss", "https://op",
        "com.c4-soft.springaddons.oidc.ops[0].authorized-parties[0]", "gateway",
        "com.c4-soft.springaddons.oidc.ops[0].authorized-parties[1]", "bruno"));

    assertThat(properties.getOps().get(0).getAuthorizedParties()).containsExactly("gateway",
        "bruno");
  }

  private static SpringAddonsOidcProperties bind(Map<String, Object> properties) {
    return new Binder(new MapConfigurationPropertySource(properties))
        .bind("com.c4-soft.springaddons.oidc", Bindable.of(SpringAddonsOidcProperties.class))
        .orElseGet(SpringAddonsOidcProperties::new);
  }

  private static OpenidProviderProperties op(URI iss, String usernameClaim) {
    final var op = new OpenidProviderProperties();
    op.setIss(iss);
    op.setUsernameClaim(usernameClaim);
    return op;
  }
}
