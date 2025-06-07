package com.c4_soft.springaddons.rest.synchronised;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
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
   * @param registration the OAuth2 client registration to use
   * @return Filter function to add Bearer authorization to {@link WebClient} requests in a servlet
   *         application. The access token being retrieved from an OAuth2 client registration, with
   *         client credentials in a resource server application, or any flow in an app is
   *         oauth2Login.
   */
  public static ExchangeFilterFunction registrationExchangeFilterFunction(
      OAuth2AuthorizedClientManager authorizedClientManager, ClientRegistration registration) {
    final var delegate =
        new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
    delegate.setDefaultClientRegistrationId(registration.getRegistrationId());
    if (registration.getAuthorizationGrantType() == AuthorizationGrantType.CLIENT_CREDENTIALS) {
      delegate.setSecurityContextHolderStrategy(new NoOpSecurityContextHolderStrategy());
    }
    return delegate;
  }

  private static class NoOpSecurityContextHolderStrategy implements SecurityContextHolderStrategy {
    private static final VoidSecurityContext securityContext = new VoidSecurityContext();

    @Override
    public void clearContext() {}

    @Override
    public SecurityContext getContext() {
      return securityContext;
    }

    @Override
    public void setContext(SecurityContext context) {}

    @Override
    public SecurityContext createEmptyContext() {
      return securityContext;
    }

    private static class VoidSecurityContext implements SecurityContext {
      private static final long serialVersionUID = 6058416562157069838L;

      @Override
      public Authentication getAuthentication() {
        return null;
      }

      @Override
      public void setAuthentication(Authentication authentication) {}
    }
  }
}
