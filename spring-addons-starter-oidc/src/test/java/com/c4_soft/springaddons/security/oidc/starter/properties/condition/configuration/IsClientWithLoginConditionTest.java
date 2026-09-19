package com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

class IsClientWithLoginConditionTest {

  @Test
  void givenNoSecurityMatchers_whenHasSecurityMatchers_thenFalse() {
    assertThat(IsClientWithLoginCondition.hasSecurityMatchers(environment(Map.of()))).isFalse();
    assertThat(IsClientWithLoginCondition.hasSecurityMatchers(
        environment(Map.of("com.c4-soft.springaddons.oidc.client.security-matchers", ""))))
            .isFalse();
    assertThat(IsClientWithLoginCondition.hasSecurityMatchers(
        environment(Map.of("com.c4-soft.springaddons.oidc.client.security-matchers[0]", " "))))
            .isFalse();
  }

  @Test
  void givenCommaSeparatedSecurityMatchers_whenHasSecurityMatchers_thenTrue() {
    assertThat(IsClientWithLoginCondition.hasSecurityMatchers(environment(
        Map.of("com.c4-soft.springaddons.oidc.client.security-matchers", "/login/**,/oauth2/**"))))
            .isTrue();
  }

  @Test
  void givenIndexedSecurityMatchers_whenHasSecurityMatchers_thenTrue() {
    assertThat(IsClientWithLoginCondition.hasSecurityMatchers(environment(
        Map.of("com.c4-soft.springaddons.oidc.client.security-matchers[0]", "/login/**",
            "com.c4-soft.springaddons.oidc.client.security-matchers[1]", "/oauth2/**"))))
                .isTrue();
  }

  private static StandardEnvironment environment(Map<String, Object> properties) {
    final var environment = new StandardEnvironment();
    environment.getPropertySources().addFirst(new MapPropertySource("test", properties));
    return environment;
  }
}
