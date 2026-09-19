package com.c4_soft.springaddons.security.oidc.starter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties.OAuth2LogoutProperties;

class SpringAddonsOAuth2LogoutRequestUriBuilderTest {

  @Test
  void givenOidcCompliantProvider_whenGetLogoutRequestUri_thenStandardParametersAreUsed() {
    final var builder = new SpringAddonsOAuth2LogoutRequestUriBuilder(
        new SpringAddonsOidcClientProperties());

    final var actual = builder.getLogoutRequestUri(
        registration(Map.of("end_session_endpoint", "https://op/logout")), "a.b.c",
        Optional.of(URI.create("https://app/ui?tab=1")));

    assertThat(actual).contains(
        "https://op/logout?id_token_hint=a.b.c&client_id=client-id&post_logout_redirect_uri=https://app/ui?tab%3D1");
  }

  @Test
  void givenLogoutPropertiesForRegistration_whenGetLogoutRequestUri_thenConfiguredUriAndParametersAreUsed() {
    final var clientProperties = new SpringAddonsOidcClientProperties();
    final var logoutProperties = new OAuth2LogoutProperties();
    logoutProperties.setUri(URI.create("https://op/v2/logout"));
    logoutProperties.setClientIdRequestParam(Optional.of("client"));
    logoutProperties.setPostLogoutUriRequestParam(Optional.of("returnTo"));
    logoutProperties.setIdTokenHintRequestParam(Optional.empty());
    clientProperties.getOauth2Logout().put("reg", logoutProperties);
    final var builder = new SpringAddonsOAuth2LogoutRequestUriBuilder(clientProperties);

    final var actual = builder.getLogoutRequestUri(registration(Map.of()), "a.b.c",
        Optional.of(URI.create("/ui")));

    assertThat(actual).contains("https://op/v2/logout?client=client-id&returnTo=/ui");
  }

  @Test
  void givenLogoutIsDisabledForRegistration_whenGetLogoutRequestUri_thenPostLogoutUri() {
    final var clientProperties = new SpringAddonsOidcClientProperties();
    final var logoutProperties = new OAuth2LogoutProperties();
    logoutProperties.setEnabled(false);
    clientProperties.getOauth2Logout().put("reg", logoutProperties);
    final var builder = new SpringAddonsOAuth2LogoutRequestUriBuilder(clientProperties);

    assertThat(builder.getLogoutRequestUri(registration(Map.of()), "a.b.c",
        Optional.of(URI.create("/ui")))).contains("/ui");
  }

  @Test
  void givenNeitherOidcConfigurationNorLogoutProperties_whenGetLogoutRequestUri_thenThrows() {
    final var builder = new SpringAddonsOAuth2LogoutRequestUriBuilder(
        new SpringAddonsOidcClientProperties());

    assertThatThrownBy(() -> builder.getLogoutRequestUri(registration(Map.of()), "a.b.c",
        Optional.of(URI.create("/ui")))).isInstanceOf(
            SpringAddonsOAuth2LogoutRequestUriBuilder.MisconfiguredProviderException.class);
  }

  private static ClientRegistration registration(Map<String, Object> configurationMetadata) {
    return ClientRegistration.withRegistrationId("reg").clientId("client-id")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("https://op/authorize").tokenUri("https://op/token")
        .providerConfigurationMetadata(configurationMetadata).build();
  }
}
