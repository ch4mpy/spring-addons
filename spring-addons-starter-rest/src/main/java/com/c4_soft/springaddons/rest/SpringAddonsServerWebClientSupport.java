package com.c4_soft.springaddons.rest;

import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * 
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
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
    return (ClientRequest request, ExchangeFunction next) -> {
      return ReactiveSecurityContextHolder.getContext().map(sch -> {
        final var auth = sch.getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AbstractOAuth2Token oauth2Token) {
          return ClientRequest.from(request)
              .headers(headers -> headers.setBearerAuth(oauth2Token.getTokenValue())).build();
        }
        return request;
      }).or(Mono.just(request)).flatMap(next::exchange);
    };
  }

  /**
   * 
   * @param clientRegistrationRepository
   * @param authorizedClientRepository
   * @param registrationId the registration ID to use (a key in
   *        "spring.security.oauth2.client.registration" properties)
   * @return Filter function to add Bearer authorization to {@link WebClient} requests in a WebFlux
   *         application. The access token being retrieved from an OAuth2 client registration, with
   *         client credentials in a resource server application, or any flow in an app is
   *         oauth2Login.
   */
  public static ExchangeFilterFunction registrationExchangeFilterFunction(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository, String registrationId) {
    final var delegate = new ServerOAuth2AuthorizedClientExchangeFilterFunction(
        clientRegistrationRepository, authorizedClientRepository);
    delegate.setDefaultClientRegistrationId(registrationId);
    return delegate;
  }
}