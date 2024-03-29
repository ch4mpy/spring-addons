package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * @deprecated replaced by {@link SpringAddonsOauth2ServerRedirectStrategy}
 */
@RequiredArgsConstructor
@Deprecated(forRemoval = true)
public class C4Oauth2ServerRedirectStrategy implements ServerRedirectStrategy {
    public static final String RESPONSE_STATUS_HEADER = "X-RESPONSE-STATUS";
    public static final String RESPONSE_LOCATION_HEADER = "X-RESPONSE-LOCATION";

    private final HttpStatus defaultStatus;

    @Override
    public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location) {
        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            final var status = Optional
                .ofNullable(exchange.getRequest().getHeaders().get(RESPONSE_STATUS_HEADER))
                .map(List::stream)
                .orElse(Stream.empty())
                .filter(StringUtils::hasLength)
                .findAny()
                .map(statusStr -> {
                    try {
                        final var statusCode = Integer.parseInt(statusStr);
                        return HttpStatus.valueOf(statusCode);
                    } catch (NumberFormatException e) {
                        return HttpStatus.valueOf(statusStr.toUpperCase());
                    }
                })
                .orElse(defaultStatus);
            response.setStatusCode(status);

            final URI url = Optional
                .ofNullable(exchange.getRequest().getHeaders().get(RESPONSE_LOCATION_HEADER))
                .map(List::stream)
                .orElse(Stream.empty())
                .filter(StringUtils::hasLength)
                .findAny()
                .map(URI::create)
                .orElse(location);
            response.getHeaders().setLocation(url);
        });
    }

}
