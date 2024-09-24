package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
public class SpringAddonsServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
    private final SpringAddonsOidcClientProperties clientProperties;

    public SpringAddonsServerAuthenticationEntryPoint(SpringAddonsOidcClientProperties addonsProperties) {
        this.clientProperties = addonsProperties;
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        final var location = clientProperties
            .getLoginUri()
            .orElse(
                UriComponentsBuilder.fromUri(clientProperties.getClientUri()).pathSegment(clientProperties.getClientUri().getPath(), "/login").build().toUri())
            .toString();
        log.debug("Status: {}, location: {}", clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().value(), location);

        final var response = exchange.getResponse();
        response.setStatusCode(clientProperties.getOauth2Redirections().getAuthenticationEntryPoint());
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "OAuth realm=%s".formatted(location));
        response.getHeaders().add(HttpHeaders.LOCATION, location.toString());

        if (clientProperties.getOauth2Redirections().getAuthenticationEntryPoint().is4xxClientError() || clientProperties
            .getOauth2Redirections()
            .getAuthenticationEntryPoint()
            .is5xxServerError()) {
            final var buffer = response.bufferFactory().wrap("Unauthorized. Please authenticate at %s".formatted(location.toString()).getBytes());
            return response.writeWith(Flux.just(buffer));
        }

        return response.setComplete();
    }
}
