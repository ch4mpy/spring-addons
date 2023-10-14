package com.c4_soft.dzone_oauth2_spring.official_bff;

import static org.springframework.security.config.Customizer.withDefaults;

import java.nio.charset.Charset;
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
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.WebFilter;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConf {

	/**
	 * <p>
	 * Security filter-chain for resources needing sessions with CSRF protection enabled and CSRF token cookie accessible to Angular
	 * application.
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
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityWebFilterChain clientFilterCHain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			@Value("${client-security-matchers:[]}") String[] securityMatchers,
			@Value("${client-permit-all:[]}") String[] permitAll,
			@Value("${post-logout-redirect-uri}") String postLogoutRedirectUri) {

		// Apply this filter-chain only to resources needing sessions
		final var clientRoutes =
				Stream.of(securityMatchers).map(PathPatternParserServerWebExchangeMatcher::new).map(ServerWebExchangeMatcher.class::cast).toList();
		http.securityMatcher(new OrServerWebExchangeMatcher(clientRoutes));

		// Set post-login URI to Angular app (login being successful or not)
		http.oauth2Login(login -> {
			login.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler("/ui/"));
			login.authenticationFailureHandler(new RedirectServerAuthenticationFailureHandler("/ui/"));
		});

		// Keycloak fully complies with RP-Initiated Logout
		http.logout(logout -> {
			logout.logoutSuccessHandler(new AngularLogoutSucessHandler(clientRegistrationRepository, postLogoutRedirectUri));
		});

		// Sessions being necessary, configure CSRF protection to work with Angular.
		// Note the csrfCookieWebFilter below which actually attaches the CSRF token cookie to responses
		http.csrf(csrf -> {
			var delegate = new XorServerCsrfTokenRequestAttributeHandler();
			csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(delegate::handle);
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
	 * It is defined with lower precedence (higher order) than the client filter-chain and no security matcher => this one acts as default for
	 * all requests that do not match the client filter-chain secutiy-matcher.
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

	static class AngularLogoutSucessHandler implements ServerLogoutSuccessHandler {
		private final OidcClientInitiatedServerLogoutSuccessHandler delegate;
		
		public AngularLogoutSucessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository, String postLogoutRedirectUri) {
			this.delegate = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
			this.delegate.setPostLogoutRedirectUri(postLogoutRedirectUri);
		}

		@Override
		public
				Mono<
						Void>
				onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
				exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
			}));
		}

	}
}
