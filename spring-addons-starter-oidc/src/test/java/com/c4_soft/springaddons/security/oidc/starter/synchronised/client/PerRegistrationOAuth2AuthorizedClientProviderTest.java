package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.context;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.registration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestToUriTemplate;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.event.OAuth2AuthorizedClientRefreshedEvent;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;

class PerRegistrationOAuth2AuthorizedClientProviderTest {

  private static final String TOKEN_RESPONSE = """
      {
        "access_token": "new-at",
        "token_type": "Bearer",
        "expires_in": 300,
        "refresh_token": "new-rt",
        "scope": "openid",
        "id_token": "new-id-token"
      }
      """;

  private final RestClient.Builder tokenClientBuilder = RestClient.builder()
      .configureMessageConverters(converters -> {
        converters.addCustomConverter(new FormHttpMessageConverter());
        converters.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter());
      }).defaultStatusHandler(new OAuth2ErrorResponseErrorHandler());
  private final MockRestServiceServer tokenEndpoint =
      MockRestServiceServer.bindTo(tokenClientBuilder).build();
  private final List<Object> publishedEvents = new ArrayList<>();

  @Test
  void givenAPublisher_whenRefresh_thenTheRefreshedEventIsPublished() {
    expectOneRefresh();
    final var provider = provider(publishedEvents::add);

    final var refreshed = provider.authorize(context("login", "ch4mp", "at", "rt"));

    tokenEndpoint.verify();
    assertThat(refreshed.getAccessToken().getTokenValue()).isEqualTo("new-at");
    assertThat(publishedEvents).singleElement()
        .isInstanceOfSatisfying(OAuth2AuthorizedClientRefreshedEvent.class, event -> {
          assertThat(event.getAuthorizedClient()).isSameAs(refreshed);
          assertThat(event.getAccessTokenResponse().getAdditionalParameters())
              .containsEntry("id_token", "new-id-token");
        });
  }

  @Test
  void givenNoPublisher_whenRefresh_thenRefreshed() {
    expectOneRefresh();
    final var provider = new PerRegistrationOAuth2AuthorizedClientProvider(
        new InMemoryClientRegistrationRepository(registration("login")),
        new SpringAddonsOidcProperties(), Map.of("login", tokenClientBuilder.build()));

    final var refreshed = provider.authorize(context("login", "ch4mp", "at", "rt"));

    tokenEndpoint.verify();
    assertThat(refreshed.getAccessToken().getTokenValue()).isEqualTo("new-at");
  }

  @Test
  void givenAListenerRefusesTheRefreshedIdentity_whenRefresh_thenClientAuthorizationExceptionWithInvalidGrantAndNoCause() {
    expectOneRefresh();
    final var provider = provider(refusingIdToken());

    assertThatThrownBy(() -> provider.authorize(context("login", "ch4mp", "at", "rt")))
        .isInstanceOfSatisfying(ClientAuthorizationException.class, e -> {
          assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
          assertThat(e.getError().getDescription()).contains("invalid_id_token")
              .contains("Invalid audience");
          assertThat(e.getClientRegistrationId()).isEqualTo("login");
          // ExceptionTranslationFilter looks for an AuthenticationException in the cause chain
          assertThat(e).hasNoCause();
        });
  }

  @Test
  void givenAListenerFailsWithAnotherException_whenRefresh_thenItIsRethrownUntouched() {
    expectOneRefresh();
    final var failure = new IllegalStateException("not an identity refusal");
    final var provider = provider(event -> {
      throw failure;
    });

    assertThatThrownBy(() -> provider.authorize(context("login", "ch4mp", "at", "rt")))
        .isSameAs(failure);
  }

  @Test
  void givenAFlowJustCompleted_whenAuthorizeWithTheSameStaleClient_thenTheEventIsPublishedOnce() {
    expectOneRefresh();
    final var provider = provider(publishedEvents::add);
    final var context = context("login", "ch4mp", "at", "rt");

    final var first = provider.authorize(context);
    final var second = provider.authorize(context);

    tokenEndpoint.verify();
    assertThat(second).isSameAs(first);
    assertThat(publishedEvents).hasSize(1);
  }

  @Test
  void givenTheRefreshedIdentityWasRefused_whenAuthorizeWithTheSameStaleClient_thenTheFailureIsReused() {
    expectOneRefresh();
    final var provider = provider(refusingIdToken());
    final var context = context("login", "ch4mp", "at", "rt");

    assertThatThrownBy(() -> provider.authorize(context))
        .isInstanceOf(ClientAuthorizationException.class);
    assertThatThrownBy(() -> provider.authorize(context))
        .isInstanceOfSatisfying(ClientAuthorizationException.class, e -> assertThat(
            e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));

    tokenEndpoint.verify();
  }

  private PerRegistrationOAuth2AuthorizedClientProvider provider(
      ApplicationEventPublisher publisher) {
    final var provider = new PerRegistrationOAuth2AuthorizedClientProvider(
        new InMemoryClientRegistrationRepository(registration("login")),
        new SpringAddonsOidcProperties(), Map.of("login", tokenClientBuilder.build()));
    provider.setApplicationEventPublisher(publisher);
    return provider;
  }

  private void expectOneRefresh() {
    tokenEndpoint.expect(once(), requestToUriTemplate("https://localhost/token"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(content()
            .formDataContains(Map.of("grant_type", "refresh_token", "refresh_token", "rt")))
        .andRespond(withSuccess(TOKEN_RESPONSE, MediaType.APPLICATION_JSON));
  }

  /**
   * What Spring Security's {@code OidcAuthorizedClientRefreshedEventListener} throws when the
   * refreshed ID token does not match the one of the login
   */
  private static ApplicationEventPublisher refusingIdToken() {
    return event -> {
      final var error = new OAuth2Error("invalid_id_token", "Invalid audience", null);
      throw new OAuth2AuthenticationException(error, error.toString());
    };
  }
}
