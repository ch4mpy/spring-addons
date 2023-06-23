package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties.RequestParam;

import reactor.core.publisher.Mono;

public class SpringAddonsServerOAuth2AuthorizationRequestResolver extends DefaultServerOAuth2AuthorizationRequestResolver {
	private static final Pattern authorizationRequestPattern = Pattern.compile("\\/oauth2\\/authorization\\/([^\\/]+)");
	private static final Consumer<OAuth2AuthorizationRequest.Builder> noOpCustomizer = builder -> {
	};

	private final Map<String, Consumer<OAuth2AuthorizationRequest.Builder>> authRequestCustomizers = new HashMap<>();

	public SpringAddonsServerOAuth2AuthorizationRequestResolver(
			InMemoryReactiveClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsOAuth2ClientProperties addonsClientProperties) {
		super(clientRegistrationRepository);
		clientRegistrationRepository.forEach(reg -> {
			final var params = addonsClientProperties.getAuthorizationRequestParams().get(reg.getRegistrationId());
			if (params != null) {
				authRequestCustomizers.put(reg.getRegistrationId(), requestParamAuthorizationRequestCustomizer(params));
			}
		});
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
		setAuthorizationRequestCustomizer(authRequestCustomizer(exchange));
		return super.resolve(exchange);
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId) {
		setAuthorizationRequestCustomizer(authRequestCustomizer(clientRegistrationId));
		return super.resolve(exchange, clientRegistrationId);
	}

	Consumer<OAuth2AuthorizationRequest.Builder> authRequestCustomizer(ServerWebExchange exchange) {
		return authRequestCustomizer(resolveRegistrationId(exchange));
	}

	Consumer<OAuth2AuthorizationRequest.Builder> authRequestCustomizer(String registrationId) {
		if (registrationId == null) {
			return noOpCustomizer;
		}
		return authRequestCustomizers.getOrDefault(registrationId, noOpCustomizer);
	}

	static String resolveRegistrationId(ServerWebExchange exchange) {
		final var requestPath = Optional.ofNullable(exchange.getRequest()).map(ServerHttpRequest::getPath).map(RequestPath::toString).orElse("");
		return resolveRegistrationId(requestPath);
	}

	static String resolveRegistrationId(String requestPath) {
		final var matcher = authorizationRequestPattern.matcher(requestPath);
		return matcher.matches() ? matcher.group(1) : null;
	}

	private static Consumer<OAuth2AuthorizationRequest.Builder> requestParamAuthorizationRequestCustomizer(RequestParam[] additionalParams) {
		return customizer -> customizer.authorizationRequestUri(authorizationRequestUri -> {
			for (var reqParam : additionalParams) {
				authorizationRequestUri.queryParam(reqParam.getName(), reqParam.getValue());
			}
			return authorizationRequestUri.build();
		});
	}

}