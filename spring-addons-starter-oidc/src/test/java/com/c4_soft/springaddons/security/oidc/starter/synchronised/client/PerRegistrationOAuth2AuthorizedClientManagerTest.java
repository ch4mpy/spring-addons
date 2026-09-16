package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class PerRegistrationOAuth2AuthorizedClientManagerTest {

  private OAuth2AuthorizedClient sessionScopedClient;
  private OAuth2AuthorizedClient applicationScopedClient;
  private PerRegistrationOAuth2AuthorizedClientManager manager;

  @BeforeEach
  void setUp() {
    sessionScopedClient = mock(OAuth2AuthorizedClient.class);
    applicationScopedClient = mock(OAuth2AuthorizedClient.class);

    final var sessionScopedDelegate = mock(OAuth2AuthorizedClientManager.class);
    when(sessionScopedDelegate.authorize(any())).thenReturn(sessionScopedClient);

    final var applicationScopedDelegate = mock(OAuth2AuthorizedClientManager.class);
    when(applicationScopedDelegate.authorize(any())).thenReturn(applicationScopedClient);

    final var clientRegistrationRepository = mock(ClientRegistrationRepository.class);
    when(clientRegistrationRepository.findByRegistrationId("login"))
        .thenReturn(registration("login", AuthorizationGrantType.AUTHORIZATION_CODE));
    when(clientRegistrationRepository.findByRegistrationId("downstream"))
        .thenReturn(registration("downstream", AuthorizationGrantType.CLIENT_CREDENTIALS));

    manager = new PerRegistrationOAuth2AuthorizedClientManager(clientRegistrationRepository,
        sessionScopedDelegate, applicationScopedDelegate);
  }

  @Test
  void givenRegistrationIsAuthorizationCode_whenAuthorize_thenSessionScopedDelegateIsUsed() {
    assertThat(manager.authorize(authorizeRequest("login"))).isSameAs(sessionScopedClient);
  }

  @Test
  void givenRegistrationIsClientCredentials_whenAuthorize_thenApplicationScopedDelegateIsUsed() {
    assertThat(manager.authorize(authorizeRequest("downstream")))
        .isSameAs(applicationScopedClient);
  }

  @Test
  void givenRegistrationIsUnknown_whenAuthorize_thenSessionScopedDelegateIsUsed() {
    assertThat(manager.authorize(authorizeRequest("unknown"))).isSameAs(sessionScopedClient);
  }

  private static OAuth2AuthorizeRequest authorizeRequest(String registrationId) {
    return OAuth2AuthorizeRequest.withClientRegistrationId(registrationId)
        .principal(new TestingAuthenticationToken("ch4mp", "secret")).build();
  }

  private static ClientRegistration registration(String registrationId,
      AuthorizationGrantType grantType) {
    return ClientRegistration.withRegistrationId(registrationId).clientId(registrationId)
        .clientSecret("secret").authorizationGrantType(grantType)
        .authorizationUri("https://localhost/auth").tokenUri("https://localhost/token")
        .redirectUri("https://localhost/login/oauth2/code/%s".formatted(registrationId)).build();
  }
}
