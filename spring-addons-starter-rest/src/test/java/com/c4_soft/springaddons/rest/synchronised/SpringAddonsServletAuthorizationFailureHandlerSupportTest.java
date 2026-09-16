package com.c4_soft.springaddons.rest.synchronised;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

class SpringAddonsServletAuthorizationFailureHandlerSupportTest {

  private static final String REGISTRATION_ID = "downstream";

  private OAuth2AuthorizedClientRepository authorizedClientRepository;
  private OAuth2AuthorizedClientService authorizedClientService;
  private Authentication principal;
  private ClientAuthorizationException exception;

  @BeforeEach
  void setUp() {
    authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
    authorizedClientService = mock(OAuth2AuthorizedClientService.class);
    principal = new TestingAuthenticationToken("ch4mp", "secret");
    exception = clientAuthorizationException(OAuth2ErrorCodes.INVALID_GRANT);
  }

  @Test
  void givenNoStore_whenRemoveAuthorizedClientFailureHandler_thenEmpty() {
    assertThat(SpringAddonsServletAuthorizationFailureHandlerSupport
        .removeAuthorizedClientFailureHandler(Optional.empty(), Optional.empty())).isEmpty();
  }

  @Test
  void givenBothStores_whenAuthorizationFails_thenTheAuthorizedClientIsRemovedFromBoth() {
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();

    handler().onAuthorizationFailure(exception, principal,
        Map.of(HttpServletRequest.class.getName(), request, HttpServletResponse.class.getName(),
            response));

    verify(authorizedClientRepository).removeAuthorizedClient(eq(REGISTRATION_ID), eq(principal),
        eq(request), eq(response));
    verify(authorizedClientService).removeAuthorizedClient(REGISTRATION_ID, principal.getName());
  }

  @Test
  void givenNoRequestInAttributes_whenAuthorizationFails_thenOnlyTheServiceIsUsed() {
    handler().onAuthorizationFailure(exception, principal, Map.of());

    verifyNoInteractions(authorizedClientRepository);
    verify(authorizedClientService).removeAuthorizedClient(REGISTRATION_ID, principal.getName());
  }

  @Test
  void givenAnErrorCodeWhichIsNotARemovalOne_whenAuthorizationFails_thenNoStoreIsTouched() {
    handler().onAuthorizationFailure(clientAuthorizationException(OAuth2ErrorCodes.SERVER_ERROR),
        principal, Map.of(HttpServletRequest.class.getName(), new MockHttpServletRequest()));

    verifyNoInteractions(authorizedClientRepository);
    verifyNoInteractions(authorizedClientService);
  }

  @Test
  void givenOnlyTheRepository_whenAuthorizationFails_thenTheAuthorizedClientIsRemovedFromIt() {
    final var request = new MockHttpServletRequest();

    SpringAddonsServletAuthorizationFailureHandlerSupport
        .removeAuthorizedClientFailureHandler(Optional.of(authorizedClientRepository),
            Optional.empty())
        .orElseThrow().onAuthorizationFailure(exception, principal,
            Map.of(HttpServletRequest.class.getName(), request));

    verify(authorizedClientRepository).removeAuthorizedClient(eq(REGISTRATION_ID), eq(principal),
        eq(request), any());
    verifyNoInteractions(authorizedClientService);
  }

  private OAuth2AuthorizationFailureHandler handler() {
    return SpringAddonsServletAuthorizationFailureHandlerSupport
        .removeAuthorizedClientFailureHandler(Optional.of(authorizedClientRepository),
            Optional.of(authorizedClientService))
        .orElseThrow();
  }

  private static ClientAuthorizationException clientAuthorizationException(String errorCode) {
    return new ClientAuthorizationException(new OAuth2Error(errorCode), REGISTRATION_ID);
  }
}
