package com.c4_soft.springaddons.security.oidc.starter.properties.condition;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class HasOAuth2RegistrationWithGrantTypeConditionTest {

  @Test
  void givenNoRegistrationProperty_whenAuthorizationGrantTypesByRegistrationId_thenEmpty() {
    assertThat(HasOAuth2RegistrationWithGrantTypeCondition
        .authorizationGrantTypesByRegistrationId(environment(Map.of()))).isEmpty();
  }

  @Test
  void givenRegistrationWithoutGrantType_whenAuthorizationGrantTypesByRegistrationId_thenAuthorizationCode() {
    final var env = environment(Map.of("spring.security.oauth2.client.registration.google.client-id",
        "client-id", "spring.security.oauth2.client.registration.google.client-secret", "secret"));

    assertThat(
        HasOAuth2RegistrationWithGrantTypeCondition.authorizationGrantTypesByRegistrationId(env))
            .containsExactly(Map.entry("google", AuthorizationGrantType.AUTHORIZATION_CODE));
  }

  @Test
  void givenRegistrationsWithDifferentGrantTypes_whenAuthorizationGrantTypesByRegistrationId_thenEachIsResolved() {
    final var env = environment(Map.of(
        "spring.security.oauth2.client.registration.bff.client-id", "bff",
        "spring.security.oauth2.client.registration.bff.authorization-grant-type",
        "authorization_code",
        "spring.security.oauth2.client.registration.downstream.client-id", "downstream",
        "spring.security.oauth2.client.registration.downstream.authorization-grant-type",
        "client_credentials"));

    assertThat(
        HasOAuth2RegistrationWithGrantTypeCondition.authorizationGrantTypesByRegistrationId(env))
            .containsOnly(Map.entry("bff", AuthorizationGrantType.AUTHORIZATION_CODE),
                Map.entry("downstream", AuthorizationGrantType.CLIENT_CREDENTIALS));
  }

  @Test
  void givenGrantTypeInCamelCase_whenAuthorizationGrantTypesByRegistrationId_thenRelaxedBindingApplies() {
    final var env = environment(
        Map.of("spring.security.oauth2.client.registration.downstream.clientId", "downstream",
            "spring.security.oauth2.client.registration.downstream.authorizationGrantType",
            "client_credentials"));

    assertThat(
        HasOAuth2RegistrationWithGrantTypeCondition.authorizationGrantTypesByRegistrationId(env))
            .containsExactly(Map.entry("downstream", AuthorizationGrantType.CLIENT_CREDENTIALS));
  }

  @Test
  void givenRegistrationWithOnlyAProvider_whenAuthorizationGrantTypesByRegistrationId_thenRegistrationIsNotSkipped() {
    final var env = environment(
        Map.of("spring.security.oauth2.client.registration.keycloak.provider", "keycloak"));

    assertThat(
        HasOAuth2RegistrationWithGrantTypeCondition.authorizationGrantTypesByRegistrationId(env))
            .containsExactly(Map.entry("keycloak", AuthorizationGrantType.AUTHORIZATION_CODE));
  }

  private static StandardEnvironment environment(Map<String, Object> properties) {
    final var environment = new StandardEnvironment();
    environment.getPropertySources().addFirst(new MapPropertySource("test", properties));
    return environment;
  }
}
