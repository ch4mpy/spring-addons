package com.c4_soft.dzone_oauth2_spring.official_bff;

import static org.springframework.security.config.Customizer.withDefaults;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConf {

	/**
	 * <p>
	 * Security filter-chain for resources needing sessions with CSRF protection enabled and CSRF token cookie accessible to Angular application.
	 * </p>
	 * <p>
	 * It is defined with low order (high precedence) and security-matcher to limit the resources it applies to.
	 * </p>
	 *
	 * @param  http
	 * @param  clientRegistrationRepository
	 * @param  securityMatchers
	 * @param  permitAll
	 * @return
	 * @throws URISyntaxException
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityWebFilterChain clientFilterCHain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			@Value("${gateway-uri}") URI gatewayUri,
			@Value("${client-security-matchers:[]}") String[] securityMatchers,
			@Value("${client-permit-all:[]}") String[] permitAll,
			@Value("${pre-authorization-status:FOUND}") HttpStatus preAuthorizationStatus,
			@Value("${post-authorization-status:FOUND}") HttpStatus postAuthorizationStatus,
			@Value("${post-logout-redirect-uri}") String postLogoutRedirectUri)
			throws URISyntaxException {

		// Apply this filter-chain only to resources needing sessions
		final var clientRoutes =
				Stream.of(securityMatchers).map(PathPatternParserServerWebExchangeMatcher::new).map(ServerWebExchangeMatcher.class::cast).toList();
		http.securityMatcher(new OrServerWebExchangeMatcher(clientRoutes));

		// The following handlers answer with NO_CONTENT HTTP status so that single page and mobile apps can handle the redirection by themselves
		http.oauth2Login(login -> {
			login.authorizationRedirectStrategy(new C4OAuth2ServerRedirectStrategy(preAuthorizationStatus));

			// Set post-login URI to Angular app (login being successful or not)
			final var uiUri = UriComponentsBuilder.fromUri(gatewayUri).path("/ui/").build().toUri();
			login.authenticationSuccessHandler(new C4Oauth2ServerAuthenticationSuccessHandler(postAuthorizationStatus, uiUri));
			login.authenticationFailureHandler(new C4Oauth2ServerAuthenticationFailureHandler(postAuthorizationStatus, uiUri));
		});

		// Keycloak fully complies with RP-Initiated Logout but we need an answer in the 2xx range for single page and mobile apps to handle the redirection by
		// themselves
		// The following is a wrapper around the OidcClientInitiatedServerLogoutSuccessHandler to change the response status.
		http.logout(logout -> {
			logout.logoutSuccessHandler(new SpaLogoutSucessHandler(clientRegistrationRepository, postLogoutRedirectUri));
		});

		// Sessions being necessary, configure CSRF protection to work with Angular.
		// Note the csrfCookieWebFilter below which actually attaches the CSRF token cookie to responses
		http.csrf(csrf -> {
			csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler());
		});

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps(withDefaults());
		}

		// @formatter:off
		http.authorizeExchange(ex -> ex
				.pathMatchers(permitAll).permitAll()
				.anyExchange().authenticated());
		// @formatter:on

		return http.build();
	}

	/**
	 * @return second half of CSRF handling for SPAs
	 */
	@Bean
	WebFilter csrfCookieWebFilter() {
		return (exchange, chain) -> {
			exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty()).subscribe();
			return chain.filter(exchange);
		};
	}

	/**
	 * <p>
	 * Security filter-chain for resources for which sessions are not needed.
	 * </p>
	 * <p>
	 * It is defined with lower precedence (higher order) than the client filter-chain and no security matcher => this one acts as default for all requests that
	 * do not match the client filter-chain secutiy-matcher.
	 * </p>
	 *
	 * @param  http
	 * @param  serverProperties
	 * @param  permitAll
	 * @return
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	SecurityWebFilterChain resourceServerFilterCHain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			@Value("${resource-server-permit-all:[]}") String[] permitAll) {
		// Enable resource server configuration with JWT decoder
		http.oauth2ResourceServer(resourceServer -> resourceServer.jwt(withDefaults()));

		// State-less session (state in access-token only)
		http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());

		// Disable CSRF because of state-less session-management
		http.csrf(csrf -> csrf.disable());

		// Return 401 (unauthorized) instead of 302 (redirect to login) when
		// authorization is missing or invalid
		http.exceptionHandling(exceptionHandling -> {
			exceptionHandling.accessDeniedHandler((var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
				var response = exchange.getResponse();
				response.setStatusCode(principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
				response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
				var dataBufferFactory = response.bufferFactory();
				var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
				return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
			}));
		});

		// If SSL enabled, disable http (https only)
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps(withDefaults());
		}

		// @formatter:off
		http.authorizeExchange(exchange -> exchange
				.pathMatchers(permitAll).permitAll()
				.anyExchange().authenticated());
		// @formatter:on

		return http.build();
	}

	@RequiredArgsConstructor
	static class C4OAuth2ServerRedirectStrategy implements ServerRedirectStrategy {
		private final HttpStatus defaultStatus;

		@Override
		public Mono<Void> sendRedirect(ServerWebExchange exchange, URI location) {
			return Mono.fromRunnable(() -> {
				ServerHttpResponse response = exchange.getResponse();
				// @formatter:off
				final var status = Optional.ofNullable(exchange.getRequest().getHeaders().get("X-RESPONSE-STATUS"))
					.map(List::stream)
					.orElse(Stream.empty())
					.filter(StringUtils::hasLength)
					.findAny()
					.map(statusStr -> {
						try {
							final var statusCode = Integer.parseInt(statusStr);
							return HttpStatus.valueOf(statusCode);
						} catch(NumberFormatException e) {
							return HttpStatus.valueOf(statusStr.toUpperCase());
						}
					})
					.orElse(defaultStatus);
				// @formatter:on
				response.setStatusCode(status);
				response.getHeaders().setLocation(location);
			});
		}

	}

	static class C4Oauth2ServerAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {
		private final URI redirectUri;
		private final C4OAuth2ServerRedirectStrategy redirectStrategy;

		public C4Oauth2ServerAuthenticationSuccessHandler(HttpStatus status, URI location) {
			this.redirectUri = location;
			this.redirectStrategy = new C4OAuth2ServerRedirectStrategy(status);
		}

		@Override
		public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
			return redirectStrategy.sendRedirect(webFilterExchange.getExchange(), redirectUri);
		}

	}

	static class C4Oauth2ServerAuthenticationFailureHandler implements ServerAuthenticationFailureHandler {
		private final URI redirectUri;
		private final C4OAuth2ServerRedirectStrategy redirectStrategy;

		public C4Oauth2ServerAuthenticationFailureHandler(HttpStatus status, URI location) {
			this.redirectUri = location;
			this.redirectStrategy = new C4OAuth2ServerRedirectStrategy(status);
		}

		@Override
		public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
			return redirectStrategy.sendRedirect(webFilterExchange.getExchange(), redirectUri);
		}
	}

	static class SpaLogoutSucessHandler implements ServerLogoutSuccessHandler {
		private final OidcClientInitiatedServerLogoutSuccessHandler delegate;

		public SpaLogoutSucessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
			this.delegate = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
			this.delegate.setPostLogoutRedirectUri(postLogoutRedirectUri);
		}

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
				exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
			}));
		}
	}

	/**
	 * Adapted from https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa
	 */
	static final class SpaCsrfTokenRequestHandler extends ServerCsrfTokenRequestAttributeHandler {
		private final ServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();

		@Override
		public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken) {
			/*
			 * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of the CsrfToken when it is rendered in the response body.
			 */
			this.delegate.handle(exchange, csrfToken);
		}

		@Override
		public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
			final var hasHeader = exchange.getRequest().getHeaders().get(csrfToken.getHeaderName()).stream().filter(StringUtils::hasText).count() > 0;
			return hasHeader ? super.resolveCsrfTokenValue(exchange, csrfToken) : this.delegate.resolveCsrfTokenValue(exchange, csrfToken);
		}
	}
}
