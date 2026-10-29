package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.context;
import static com.c4_soft.springaddons.security.oidc.starter.AuthorizedClientTestFixtures.registration;
import static org.assertj.core.api.Assertions.assertThat;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import reactor.core.publisher.Mono;

class PerRegistrationReactiveOAuth2AuthorizedClientProviderTest {

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

  private final AtomicInteger tokenRequests = new AtomicInteger();
  private final WebClient tokenClient =
      WebClient.builder().exchangeFunction(request -> Mono.fromSupplier(() -> {
        tokenRequests.incrementAndGet();
        return ClientResponse.create(HttpStatus.OK)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .body(TOKEN_RESPONSE).build();
      })).build();
  private final OAuth2AuthorizationContext staleContext = context("login", "ch4mp", "at", "rt");

  @Test
  void givenAHandler_whenRefresh_thenItIsCalledWithTheRefreshedClientAndTheIdToken() {
    final var handled = new AtomicReference<OAuth2AuthorizedClient>();
    final var attributes = new HashMap<String, Object>();
    final var provider = provider((authorizedClient, principal, attrs) -> {
      handled.set(authorizedClient);
      attributes.putAll(attrs);
      return Mono.empty();
    });

    final var refreshed = provider.authorize(staleContext).block();

    assertThat(refreshed.getAccessToken().getTokenValue()).isEqualTo("new-at");
    assertThat(handled).hasValue(refreshed);
    assertThat(attributes).containsEntry("id_token", "new-id-token");
  }

  @Test
  void givenNoHandlerSet_whenRefreshForAPrincipalWhichIsNotAnOAuth2Login_thenRefreshed() {
    final var provider = provider();

    final var refreshed = provider.authorize(staleContext).block();

    assertThat(refreshed.getAccessToken().getTokenValue()).isEqualTo("new-at");
  }

  @Test
  void givenTheHandlerRefusesTheRefreshedIdentity_whenRefresh_thenClientAuthorizationExceptionWithInvalidGrantAndNoCause() {
    final var refusal = new OAuth2AuthenticationException(
        new OAuth2Error("invalid_id_token", "Invalid audience", null));
    final var provider = provider((authorizedClient, principal, attrs) -> Mono.error(refusal));

    assertThat(errorOf(provider.authorize(staleContext)))
        .isInstanceOfSatisfying(ClientAuthorizationException.class, e -> {
          assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
          assertThat(e.getError().getDescription()).contains("invalid_id_token")
              .contains("Invalid audience");
          assertThat(e.getClientRegistrationId()).isEqualTo("login");
          assertThat(e).hasNoCause();
          assertThat(e.getSuppressed()).containsExactly(refusal);
        });
  }

  @Test
  void givenTheHandlerRefusesTheRefreshedUser_whenRefresh_thenClientAuthorizationExceptionWithInvalidGrantAndNoCause() {
    final var refusal = new DisabledException("User is disabled");
    final var provider = provider((authorizedClient, principal, attrs) -> Mono.error(refusal));

    assertThat(errorOf(provider.authorize(staleContext)))
        .isInstanceOfSatisfying(ClientAuthorizationException.class, e -> {
          assertThat(e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
          assertThat(e.getError().getDescription()).contains("User is disabled");
          assertThat(e).hasNoCause();
          assertThat(e.getSuppressed()).containsExactly(refusal);
        });
  }

  @Test
  void givenTheHandlerThrowsInsteadOfSignaling_whenRefresh_thenClientAuthorizationExceptionWithInvalidGrant() {
    final var provider = provider((authorizedClient, principal, attrs) -> {
      throw new DisabledException("User is disabled");
    });

    assertThat(errorOf(provider.authorize(staleContext)))
        .isInstanceOfSatisfying(ClientAuthorizationException.class, e -> assertThat(
            e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));
  }

  @Test
  void givenTheHandlerFailsWithAnotherException_whenRefresh_thenItIsSignaledUntouched() {
    final var failure = new IllegalStateException("not an identity refusal");
    final var provider = provider((authorizedClient, principal, attrs) -> Mono.error(failure));

    assertThat(errorOf(provider.authorize(staleContext))).isSameAs(failure);
  }

  @Test
  void givenTheRefreshedIdentityWasRefused_whenAuthorizeWithTheSameStaleClient_thenTheFailureIsReused() {
    final var provider = provider((authorizedClient, principal, attrs) -> Mono
        .error(new OAuth2AuthenticationException(new OAuth2Error("invalid_id_token"))));

    assertThat(errorOf(provider.authorize(staleContext)))
        .isInstanceOf(ClientAuthorizationException.class);
    assertThat(errorOf(provider.authorize(staleContext)))
        .isInstanceOfSatisfying(ClientAuthorizationException.class, e -> assertThat(
            e.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT));

    assertThat(tokenRequests).hasValue(1);
  }

  private PerRegistrationReactiveOAuth2AuthorizedClientProvider provider() {
    return new PerRegistrationReactiveOAuth2AuthorizedClientProvider(
        new InMemoryReactiveClientRegistrationRepository(registration("login")),
        new SpringAddonsOidcProperties(), Map.of("login", tokenClient));
  }

  private PerRegistrationReactiveOAuth2AuthorizedClientProvider provider(
      ReactiveOAuth2AuthorizationSuccessHandler refreshTokenSuccessHandler) {
    final var provider = provider();
    provider.setRefreshTokenSuccessHandler(refreshTokenSuccessHandler);
    return provider;
  }

  /**
   * The error signaled by the given publisher, as is: {@code block()} would add a suppressed
   * exception to it
   */
  private static Throwable errorOf(Mono<?> publisher) {
    return publisher.then(Mono.<Throwable>empty()).onErrorResume(Mono::just).block();
  }
}
