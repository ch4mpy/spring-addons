package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.AdditionalParamsAuthorizationRequestCustomizer;
import com.c4_soft.springaddons.security.oidc.starter.CompositeOAuth2AuthorizationRequestCustomizer;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Serves three purposes:
 * <ul>
 * <li>Use the {@link SpringAddonsOidcClientProperties#clientUri SpringAddonsOidcClientProperties#client-uri} to set the base URI of
 * authorization-code callback (of interest for instance when using an ingress or another gateway in front of the OAuth2 client with
 * oauth2Login)</li>
 * <li>Add the query params taken from authorization-request-params in application properties</li>
 * <li>Save in session post-login URIs provided as header ({@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_HEADER}
 * and {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_HEADER}) or request param
 * ({@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_PARAM} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_PARAM}). If both are provided, header wins. The key used in
 * session are {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE} and
 * {@link SpringAddonsOidcClientProperties#POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE}.</li>
 * </ul>
 * The post-login URIs are used by the default {@link ServerAuthenticationSuccessHandler} and {@link ServerAuthenticationFailureHandler}
 * <p>
 * When needing fancy request customizers (for instance to add parameters with name or value computed at runtime), you may extend this class
 * and register your additional parameters against getCompositeOAuth2AuthorizationRequestCustomizer()
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    SpringAddonsOidcClientProperties for header and request parameter constants definitions
 * @see    SpringAddonsOauth2ServerAuthenticationSuccessHandler
 * @see    SpringAddonsOauth2ServerAuthenticationFailureHandler
 */
@Slf4j
public class SpringAddonsServerOAuth2AuthorizationRequestResolver implements ServerOAuth2AuthorizationRequestResolver {

	private static final Pattern authorizationRequestPattern = Pattern.compile("\\/oauth2\\/authorization\\/([^\\/]+)");

	private final URI clientUri;
	private final Map<String, CompositeOAuth2AuthorizationRequestCustomizer> requestCustomizers;
	private final Map<String, DefaultServerOAuth2AuthorizationRequestResolver> delegates;
	private final ServerWebExchangeMatcher authorizationRequestMatcher;

	public SpringAddonsServerOAuth2AuthorizationRequestResolver(
			OAuth2ClientProperties bootClientProperties,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsOidcClientProperties addonsClientProperties) {
		this.clientUri = addonsClientProperties.getClientUri();
		this.authorizationRequestMatcher =
				new PathPatternParserServerWebExchangeMatcher(DefaultServerOAuth2AuthorizationRequestResolver.DEFAULT_AUTHORIZATION_REQUEST_PATTERN);

		this.requestCustomizers = bootClientProperties.getRegistration().entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, registrationEntry -> {
			final var requestCustomizer = new CompositeOAuth2AuthorizationRequestCustomizer();

			final var additionalProperties = addonsClientProperties.getExtraAuthorizationParameters(registrationEntry.getKey());
			if (additionalProperties.size() > 0) {
				requestCustomizer.addCustomizer(new AdditionalParamsAuthorizationRequestCustomizer(additionalProperties));
			}

			if (addonsClientProperties.isPkceForced()) {
				requestCustomizer.addCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
			}

			return requestCustomizer;
		}));

		this.delegates = requestCustomizers.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, e -> {
			final var delegate = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);

			delegate.setAuthorizationRequestCustomizer(e.getValue());

			return delegate;
		}));
	}

	private Mono<WebSession> savePostLoginUrisInSession(ServerWebExchange exchange) {
		final var request = exchange.getRequest();
		final var headers = request.getHeaders();
		final var params = request.getQueryParams();
		return exchange.getSession().map(session -> {
			Optional.ofNullable(
					Optional.ofNullable(headers.getFirst(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER))
							.orElse(Optional.ofNullable(params.getFirst(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_PARAM)).orElse(null)))
					.filter(StringUtils::hasText).map(URI::create).ifPresent(postLoginSuccessUri -> {
						session.getAttributes().put(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, postLoginSuccessUri);
					});

			Optional.ofNullable(
					Optional.ofNullable(headers.getFirst(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER))
							.orElse(Optional.ofNullable(params.getFirst(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM)).orElse(null)))
					.filter(StringUtils::hasText).map(URI::create).ifPresent(postLoginFailureUri -> {
						session.getAttributes().put(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, postLoginFailureUri);
					});

			return session;
		});
	}

	private OAuth2AuthorizationRequest postProcess(OAuth2AuthorizationRequest request) {
		final var modified = OAuth2AuthorizationRequest.from(request);

		final var original = URI.create(request.getRedirectUri());
		final var redirectUri =
				UriComponentsBuilder.fromUri(clientUri).path(original.getPath()).query(original.getQuery()).fragment(original.getFragment()).build().toString();
		modified.redirectUri(redirectUri);

		log.debug("Changed OAuth2AuthorizationRequest redirectUri from {} to {}", original, redirectUri);
		return modified.build();
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
		// @formatter:off
		return this.authorizationRequestMatcher
				.matches(exchange)
				.filter((matchResult) -> matchResult.isMatch())
				.map(ServerWebExchangeMatcher.MatchResult::getVariables)
				.map((variables) -> variables.get(DefaultServerOAuth2AuthorizationRequestResolver.DEFAULT_REGISTRATION_ID_URI_VARIABLE_NAME))
				.cast(String.class)
				.flatMap((clientRegistrationId) -> resolve(exchange, clientRegistrationId));
		// @formatter:on
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId) {
		final var delegate = delegates.get(clientRegistrationId);
		return savePostLoginUrisInSession(exchange).then(delegate.resolve(exchange, clientRegistrationId).map(this::postProcess));
	}

	/**
	 * Use this to add a your own request customizers (for instance when needing parameters with name or value computed at runtime)
	 * 
	 * @return
	 */
	protected CompositeOAuth2AuthorizationRequestCustomizer getCompositeOAuth2AuthorizationRequestCustomizer(String registrationId) {
		return this.requestCustomizers.get(registrationId);
	}

	static String resolveRegistrationId(ServerWebExchange exchange) {
		final var requestPath = Optional.ofNullable(exchange.getRequest()).map(ServerHttpRequest::getPath).map(RequestPath::toString).orElse("");
		return resolveRegistrationId(requestPath);
	}

	static String resolveRegistrationId(String requestPath) {
		final var matcher = authorizationRequestPattern.matcher(requestPath);
		return matcher.matches() ? matcher.group(1) : null;
	}

}
