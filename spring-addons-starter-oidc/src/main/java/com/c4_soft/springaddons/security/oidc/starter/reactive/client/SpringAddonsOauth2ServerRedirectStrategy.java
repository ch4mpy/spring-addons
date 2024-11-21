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

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

/**
 * A redirect strategy that might not actually redirect: the HTTP status is taken from
 * com.c4-soft.springaddons.oidc.client.oauth2-redirect-status property. User-agents will auto redirect only if the status is in 3xx range.
 * This gives single page and mobile applications a chance to intercept the redirection and choose to follow the redirection (or not), with
 * which agent and potentially by clearing some headers.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public class SpringAddonsOauth2ServerRedirectStrategy implements ServerRedirectStrategy {

	@Getter
	private final HttpStatus defaultStatus;

	@Override
	public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location) {
		return Mono.fromRunnable(() -> {
			ServerHttpResponse response = exchange.getResponse();
			final var status = Optional.ofNullable(exchange.getRequest().getHeaders().get(SpringAddonsOidcClientProperties.RESPONSE_STATUS_HEADER))
					.map(List::stream).orElse(Stream.empty()).filter(StringUtils::hasLength).findAny().map(statusStr -> {
						try {
							final var statusCode = Integer.parseInt(statusStr);
							return HttpStatus.valueOf(statusCode);
						} catch (NumberFormatException e) {
							return HttpStatus.valueOf(statusStr.toUpperCase());
						}
					}).orElse(defaultStatus);
			response.setStatusCode(status);

			response.getHeaders().setLocation(location);
		});
	}
}
