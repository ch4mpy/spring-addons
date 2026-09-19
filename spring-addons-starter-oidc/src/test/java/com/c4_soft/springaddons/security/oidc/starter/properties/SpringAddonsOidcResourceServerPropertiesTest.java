package com.c4_soft.springaddons.security.oidc.starter.properties;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

class SpringAddonsOidcResourceServerPropertiesTest {

  @Test
  void givenNoProperty_whenBind_thenSessionsAreStateless() {
    assertThat(bind(Map.of()).isStatelessSessions()).isTrue();
  }

  @Test
  void givenStatelessSessionsProperty_whenBind_thenBound() {
    assertThat(bind(Map.of("com.c4-soft.springaddons.oidc.resourceserver.stateless-sessions",
        "false")).isStatelessSessions()).isFalse();
  }

  @Test
  @SuppressWarnings("removal")
  void givenDeprecatedStatlessSessionsProperty_whenBind_thenStillBound() {
    final var properties = bind(
        Map.of("com.c4-soft.springaddons.oidc.resourceserver.statless-sessions", "false"));

    assertThat(properties.isStatelessSessions()).isFalse();
    assertThat(properties.isStatlessSessions()).isFalse();
  }

  private static SpringAddonsOidcResourceServerProperties bind(Map<String, Object> properties) {
    return new Binder(new MapConfigurationPropertySource(properties))
        .bind("com.c4-soft.springaddons.oidc.resourceserver",
            Bindable.of(SpringAddonsOidcResourceServerProperties.class))
        .orElseGet(SpringAddonsOidcResourceServerProperties::new);
  }
}
