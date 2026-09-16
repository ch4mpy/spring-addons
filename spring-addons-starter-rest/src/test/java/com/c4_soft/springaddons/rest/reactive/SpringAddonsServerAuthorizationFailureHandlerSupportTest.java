package com.c4_soft.springaddons.rest.reactive;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

class SpringAddonsServerAuthorizationFailureHandlerSupportTest {

  private static final String REGISTRATION_ID = "downstream";

  private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
  private ReactiveOAuth2AuthorizedClientService authorizedClientService;
  private Authentication principal;
  private ClientAuthorizationException exception;

  @BeforeEach
  void setUp() {
    authorizedClientRepository = mock(ServerOAuth2AuthorizedClientRepository.class);
    when(authorizedClientRepository.removeAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());

    authorizedClientService = mock(ReactiveOAuth2AuthorizedClientService.class);
    when(authorizedClientService.removeAuthorizedClient(any(), any())).thenReturn(Mono.empty());

    principal = new TestingAuthenticationToken("ch4mp", "secret");
    exception = clientAuthorizationException(OAuth2ErrorCodes.INVALID_GRANT);
  }

  @Test
  void givenNoStore_whenRemoveAuthorizedClientFailureHandler_thenEmpty() {
    assertThat(SpringAddonsServerAuthorizationFailureHandlerSupport
        .removeAuthorizedClientFailureHandler(Optional.empty(), Optional.empty())).isEmpty();
  }

  @Test
  void givenBothStores_whenAuthorizationFails_thenTheAuthorizedClientIsRemovedFromBoth() {
    final var exchange = exchange();

    handler()
        .onAuthorizationFailure(exception, principal,
            Map.of(ServerWebExchange.class.getName(), exchange))
        .block();

    verify(authorizedClientRepository).removeAuthorizedClient(REGISTRATION_ID, principal, exchange);
    verify(authorizedClientService).removeAuthorizedClient(REGISTRATION_ID, principal.getName());
  }

  @Test
  void givenNoExchangeInAttributes_whenAuthorizationFails_thenOnlyTheServiceIsUsed() {
    handler().onAuthorizationFailure(exception, principal, Map.of()).block();

    verifyNoInteractions(authorizedClientRepository);
    verify(authorizedClientService).removeAuthorizedClient(REGISTRATION_ID, principal.getName());
  }

  @Test
  void givenAnErrorCodeWhichIsNotARemovalOne_whenAuthorizationFails_thenNoStoreIsTouched() {
    handler()
        .onAuthorizationFailure(clientAuthorizationException(OAuth2ErrorCodes.SERVER_ERROR),
            principal, Map.of(ServerWebExchange.class.getName(), exchange()))
        .block();

    verifyNoInteractions(authorizedClientRepository);
    verifyNoInteractions(authorizedClientService);
  }

  @Test
  void givenOnlyTheRepository_whenAuthorizationFails_thenTheAuthorizedClientIsRemovedFromIt() {
    final var exchange = exchange();

    SpringAddonsServerAuthorizationFailureHandlerSupport
        .removeAuthorizedClientFailureHandler(Optional.of(authorizedClientRepository),
            Optional.empty())
        .orElseThrow()
        .onAuthorizationFailure(exception, principal,
            Map.of(ServerWebExchange.class.getName(), exchange))
        .block();

    verify(authorizedClientRepository).removeAuthorizedClient(REGISTRATION_ID, principal, exchange);
    verifyNoInteractions(authorizedClientService);
  }

  private ReactiveOAuth2AuthorizationFailureHandler handler() {
    return SpringAddonsServerAuthorizationFailureHandlerSupport
        .removeAuthorizedClientFailureHandler(Optional.of(authorizedClientRepository),
            Optional.of(authorizedClientService))
        .orElseThrow();
  }

  private static MockServerWebExchange exchange() {
    return MockServerWebExchange
        .from(MockServerHttpRequest.method(HttpMethod.GET, "https://localhost/downstream"));
  }

  private static ClientAuthorizationException clientAuthorizationException(String errorCode) {
    return new ClientAuthorizationException(new OAuth2Error(errorCode), REGISTRATION_ID);
  }
}
