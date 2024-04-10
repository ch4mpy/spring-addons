package com.c4_soft.springaddons.rest;

import java.util.Optional;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
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
 * Also provides with helper methods to get {@link HttpExchange @&#64;HttpExchange} proxies with {@link WebClient}
 * </p>
 * <p>
 * <b>/!\ Auto-configured only in servlet (WebMVC) applications and only if some {@link SpringAddonsRestProperties} are present /!\</b>
 * </p>
 *
 * @author Jerome Wacongne chl4mp&#64;c4-soft.com
 * @see ReactiveSpringAddonsWebClientSupport an equivalent for reactive (Webflux) applications
 */
public class SpringAddonsWebClientSupport extends AbstractSpringAddonsWebClientSupport {

    private final Optional<OAuth2AuthorizedClientManager> authorizedClientManager;

    public SpringAddonsWebClientSupport(
            SpringAddonsRestProperties addonsProperties,
            BearerProvider forwardingBearerProvider,
            Optional<OAuth2AuthorizedClientManager> authorizedClientManager) {
        super(addonsProperties, forwardingBearerProvider);
        this.authorizedClientManager = authorizedClientManager;
    }

    @Override
    protected ExchangeFilterFunction oauth2RegistrationFilter(String registrationId) {
        return (ClientRequest request, ExchangeFunction next) -> {
            final var provider = authorizedClientManager.map(acm -> new AuthorizedClientBearerProvider(acm, registrationId));
            if (provider.flatMap(AuthorizedClientBearerProvider::getBearer).isPresent()) {
                final var modified = ClientRequest.from(request).headers(headers -> headers.setBearerAuth(provider.get().getBearer().get())).build();
                return next.exchange(modified);
            }
            return next.exchange(request);
        };
    }
}
