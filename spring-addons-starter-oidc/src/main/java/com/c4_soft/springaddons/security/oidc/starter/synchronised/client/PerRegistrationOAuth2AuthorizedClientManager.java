package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * An {@link OAuth2AuthorizedClientManager} for applications mixing registrations with the
 * {@code authorization_code} flow and registrations with another flow (usually
 * {@code client_credentials}). It delegates to one of two managers, depending on the
 * {@link AuthorizationGrantType} of the registration to authorize:
 * </p>
 * <ul>
 * <li>{@code authorization_code} registrations go to a "session scoped" manager, usually a
 * {@link DefaultOAuth2AuthorizedClientManager} storing the authorized clients in an
 * {@link OAuth2AuthorizedClientRepository}: tokens are bound to a user and to the request in which
 * they were obtained</li>
 * <li>all other registrations go to an "application scoped" manager, usually an
 * {@link AuthorizedClientServiceOAuth2AuthorizedClientManager} storing the authorized clients in an
 * {@link OAuth2AuthorizedClientService}: tokens are reused across requests and no
 * {@code HttpServletRequest} is required to obtain one</li>
 * </ul>
 * <p>
 * Registrations which are unknown to the {@link ClientRegistrationRepository} are routed to the
 * session scoped manager, which is what Spring Security does by default.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public final class PerRegistrationOAuth2AuthorizedClientManager
    implements OAuth2AuthorizedClientManager {

  private final ClientRegistrationRepository clientRegistrationRepository;
  private final OAuth2AuthorizedClientManager sessionScopedDelegate;
  private final OAuth2AuthorizedClientManager applicationScopedDelegate;

  @Override
  public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
    return delegateFor(authorizeRequest.getClientRegistrationId()).authorize(authorizeRequest);
  }

  private OAuth2AuthorizedClientManager delegateFor(String registrationId) {
    final var registration = registrationId == null ? null
        : clientRegistrationRepository.findByRegistrationId(registrationId);
    if (registration == null || AuthorizationGrantType.AUTHORIZATION_CODE
        .equals(registration.getAuthorizationGrantType())) {
      return sessionScopedDelegate;
    }
    return applicationScopedDelegate;
  }
}
