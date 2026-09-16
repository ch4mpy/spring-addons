package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * <p>
 * A {@link ReactiveOAuth2AuthorizedClientManager} for applications mixing registrations with the
 * {@code authorization_code} flow and registrations with another flow (usually
 * {@code client_credentials}). It delegates to one of two managers, depending on the
 * {@link AuthorizationGrantType} of the registration to authorize:
 * </p>
 * <ul>
 * <li>{@code authorization_code} registrations go to a "session scoped" manager, usually a
 * {@link DefaultReactiveOAuth2AuthorizedClientManager} storing the authorized clients in a
 * {@link ServerOAuth2AuthorizedClientRepository}: tokens are bound to a user and to the exchange in
 * which they were obtained</li>
 * <li>all other registrations go to an "application scoped" manager, usually an
 * {@link AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager} storing the authorized
 * clients in a {@link ReactiveOAuth2AuthorizedClientService}: tokens are reused across requests and
 * no {@code ServerWebExchange} is required to obtain one</li>
 * </ul>
 * <p>
 * Registrations which are unknown to the {@link ReactiveClientRegistrationRepository} are routed to
 * the session scoped manager, which is what Spring Security does by default.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public final class PerRegistrationReactiveOAuth2AuthorizedClientManager
    implements ReactiveOAuth2AuthorizedClientManager {

  private final ReactiveClientRegistrationRepository clientRegistrationRepository;
  private final ReactiveOAuth2AuthorizedClientManager sessionScopedDelegate;
  private final ReactiveOAuth2AuthorizedClientManager applicationScopedDelegate;

  @Override
  public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizeRequest authorizeRequest) {
    return delegateFor(authorizeRequest.getClientRegistrationId())
        .flatMap(delegate -> delegate.authorize(authorizeRequest));
  }

  private Mono<ReactiveOAuth2AuthorizedClientManager> delegateFor(String registrationId) {
    if (registrationId == null) {
      return Mono.just(sessionScopedDelegate);
    }
    return clientRegistrationRepository.findByRegistrationId(registrationId)
        .map(registration -> AuthorizationGrantType.AUTHORIZATION_CODE
            .equals(registration.getAuthorizationGrantType()) ? sessionScopedDelegate
                : applicationScopedDelegate)
        .defaultIfEmpty(sessionScopedDelegate);
  }
}
