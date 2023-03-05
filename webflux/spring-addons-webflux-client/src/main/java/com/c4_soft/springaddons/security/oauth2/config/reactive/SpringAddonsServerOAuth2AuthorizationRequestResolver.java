package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.net.URI;

import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;

import reactor.core.publisher.Mono;

/**
 * Forces the usage of {@link SpringAddonsOAuth2ClientProperties#getClientUri()
 * SpringAddonsOAuth2ClientProperties#client-uri} in post-login redirection URI
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 *
 */
public class SpringAddonsServerOAuth2AuthorizationRequestResolver implements ServerOAuth2AuthorizationRequestResolver {

    private final ServerOAuth2AuthorizationRequestResolver defaultResolver;
    private final URI clientUri;

    public SpringAddonsServerOAuth2AuthorizationRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository,
            URI clientUri) {
        defaultResolver = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        this.clientUri = clientUri;
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
        return defaultResolver.resolve(exchange).map(this::toAbsolute);
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId) {
        return defaultResolver.resolve(exchange, clientRegistrationId).map(this::toAbsolute);
    }

    private OAuth2AuthorizationRequest toAbsolute(OAuth2AuthorizationRequest req) {
        if (req == null) {
            return null;
        }
        final var redirectUri = UriComponentsBuilder.fromUriString(req.getRedirectUri())
                .scheme(clientUri.getScheme()).host(clientUri.getHost())
                .port(clientUri.getPort()).build().toUriString();
        return OAuth2AuthorizationRequest.from(req).redirectUri(redirectUri).build();
    }
}