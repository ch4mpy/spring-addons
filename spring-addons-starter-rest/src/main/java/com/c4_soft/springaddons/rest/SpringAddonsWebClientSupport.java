package com.c4_soft.springaddons.rest;

import java.util.Optional;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.annotation.HttpExchange;

/**
 * <p>
 * Provides with {@link WebClient} builder instances pre-configured with:
 * </p>
 * <ul>
 * <li>HTTP conector if proxy properties or environment variables are set</li>
 * <li>Base URL</li>
 * <li>authorization exchange function if Basic or OAuth2 Bearer</li>
 * </ul>
 * <p>
 * <p>
 * Also provides with helper methods to get {@link HttpExchange @&#64;HttpExchange} proxies with
 * {@link WebClient}
 * </p>
 * <p>
 * <b>/!\ Auto-configured only in servlet (WebMVC) applications and only if some
 * {@link SpringAddonsRestProperties} are present /!\</b>
 * </p>
 *
 * @author Jerome Wacongne chl4mp&#64;c4-soft.com
 * @see ServerSpringAddonsWebClientSupport an equivalent for reactive (Webflux) applications
 */
public class SpringAddonsWebClientSupport extends AbstractSpringAddonsWebClientSupport {

  private final ClientRegistrationRepository clientRegistrationRepository;
  private final OAuth2AuthorizedClientRepository authorizedClientRepository;

  public SpringAddonsWebClientSupport(SystemProxyProperties systemProxyProperties,
      SpringAddonsRestProperties addonsProperties,
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientRepository authorizedClientRepository,
      Optional<ReactiveBearerProvider> bearerProvider) {
    super(systemProxyProperties, addonsProperties, bearerProvider);
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.authorizedClientRepository = authorizedClientRepository;
  }

  @Override
  protected ExchangeFilterFunction oauth2RegistrationFilter(String registrationId) {
    final var exchangeFilterFunction = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
        clientRegistrationRepository, authorizedClientRepository);
    exchangeFilterFunction.setDefaultClientRegistrationId(registrationId);
    return exchangeFilterFunction;
  }
}
