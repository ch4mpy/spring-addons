package com.c4_soft.springaddons.rest;

import java.util.Optional;

import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.service.annotation.HttpExchange;

import reactor.core.publisher.Mono;

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
public class ReactiveSpringAddonsWebClientSupport extends AbstractSpringAddonsWebClientSupport {

    private final Optional<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager;

    public ReactiveSpringAddonsWebClientSupport(
            SpringAddonsRestProperties addonsProperties,
            BearerProvider forwardingBearerProvider,
            Optional<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager) {
        super(addonsProperties, forwardingBearerProvider);
        this.authorizedClientManager = authorizedClientManager;
    }

    @Override
    protected ExchangeFilterFunction oauth2RegistrationFilter(String registrationId) {
        return (ClientRequest request, ExchangeFunction next) -> {
            final var provider = Mono.justOrEmpty(authorizedClientManager.map(acm -> new ReactiveAuthorizedClientBearerProvider(acm, registrationId)));
            return provider.flatMap(ReactiveAuthorizedClientBearerProvider::getBearer).defaultIfEmpty("").flatMap(bearer -> {
                if (StringUtils.hasText(bearer)) {
                    final var modified = ClientRequest.from(request).headers(headers -> headers.setBearerAuth(bearer)).build();
                    return next.exchange(modified);
                }
                return next.exchange(request);
            });
        };
    }
}
