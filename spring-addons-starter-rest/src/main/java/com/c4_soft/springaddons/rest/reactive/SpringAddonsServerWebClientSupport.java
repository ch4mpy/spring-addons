package com.c4_soft.springaddons.rest.reactive;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Objects;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsServerWebClientSupport {

  /**
   * @return Filter function to add Bearer authorization to {@link WebClient} requests in a WebFlux
   *         application. The access token being retrieved from the security context, the
   *         application must be a resource server. If the context is anonymous (the parent request
   *         is not authorized), then the child request is anonymous too (no authorization header is
   *         set).
   */
  public static ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return (ClientRequest request, ExchangeFunction next) -> ReactiveSecurityContextHolder.getContext()
            .filter(securityContext -> Objects.nonNull(securityContext.getAuthentication()))
            .map(SecurityContext::getAuthentication)
            .map(Authentication::getPrincipal)
            .ofType(AbstractOAuth2Token.class)
            .map(oauth2Token -> ClientRequest.from(request)
                    .headers(headers -> headers.setBearerAuth(oauth2Token.getTokenValue()))
                    .build()
            ).defaultIfEmpty(request)
            .flatMap(next::exchange);
  }

  /**
   * 
   * @param authorizedClientManager
   * @param registrationId the registration ID to use (a key in
   *        "spring.security.oauth2.client.registration" properties)
   * @return Filter function to add Bearer authorization to {@link WebClient} requests in a WebFlux
   *         application. The access token being retrieved from an OAuth2 client registration, with
   *         client credentials in a resource server application, or any flow in an app is
   *         oauth2Login.
   */
  public static ExchangeFilterFunction registrationExchangeFilterFunction(
      ReactiveOAuth2AuthorizedClientManager authorizedClientManager, String registrationId) {
    final var delegate =
        new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
    delegate.setDefaultClientRegistrationId(registrationId);
    return delegate;
  }
}
