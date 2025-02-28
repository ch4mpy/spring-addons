package com.c4_soft.springaddons.rest.synchronised;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * 
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsServletWebClientSupport {
  /**
   * @return Filter function to add Bearer authorization to {@link WebClient} requests in a servlet
   *         application. The access token being retrieved from the security context, the
   *         application must be a resource server. If the context is anonymous (the parent request
   *         is not authorized), then the child request is anonymous too (no authorization header is
   *         set).
   */
  public static ExchangeFilterFunction forwardingBearerExchangeFilterFunction() {
    return (ClientRequest request, ExchangeFunction next) -> {
      final var auth = SecurityContextHolder.getContext().getAuthentication();
      if (auth != null && auth.getPrincipal() instanceof AbstractOAuth2Token oauth2Token) {
        return next.exchange(ClientRequest.from(request)
            .headers(headers -> headers.setBearerAuth(oauth2Token.getTokenValue())).build());
      }
      return next.exchange(request);
    };
  }

  /**
   * 
   * @param authorizedClientManager
   * @param registrationId the registration ID to use (a key in
   *        "spring.security.oauth2.client.registration" properties)
   * @return Filter function to add Bearer authorization to {@link WebClient} requests in a servlet
   *         application. The access token being retrieved from an OAuth2 client registration, with
   *         client credentials in a resource server application, or any flow in an app is
   *         oauth2Login.
   */
  public static ExchangeFilterFunction registrationExchangeFilterFunction(
      OAuth2AuthorizedClientManager authorizedClientManager, String registrationId) {
    final var delegate =
        new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
    delegate.setDefaultClientRegistrationId(registrationId);
    return delegate;
  }
}
