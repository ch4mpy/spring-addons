package com.c4soft.springaddons.samples.bff.gateway;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.servlet.server.Session.Cookie;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.reactive.SpringAddonsOAuth2ClientBeans;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebSecurityConfig {

	/**
	 * Some beans here after are auto-configured by {@link SpringAddonsOAuth2ClientBeans}. Refer to its Javadoc (or source) for details.
	 *
	 * @param  http
	 * @param  serverProperties
	 * @param  clientRegistrationRepository
	 * @param  gatewayUri
	 * @param  authorizationRequestResolver
	 * @param  addonsProperties
	 * @param  corsConfigurationSource
	 * @return
	 * @throws Exception
	 */
	@Order(Ordered.HIGHEST_PRECEDENCE)
	@Bean
	SecurityWebFilterChain clientFilterChain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			@Value("${gateway-uri}") URI gatewayUri,
			ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
			SpringAddonsSecurityProperties addonsProperties,
			CorsConfigurationSource corsConfigurationSource)
			throws Exception {
		// @formatter:off
		// securityMatcher is restricted to UI resources and we want all to be accessible to anonymous
	    http.authorizeExchange().pathMatchers("/", "/login/**", "/login-options", "/oauth2/**", "/ui/**", "/v3/api-docs/**").permitAll()
	    	.anyExchange().authenticated();

	    http.exceptionHandling(exceptionHandling -> exceptionHandling
		  // redirect unauthorized request to the Angular UI which exposes a public landing page and identity provider selection
		  .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/ui")))
	    	.oauth2Login(oauth2 -> oauth2
		  // override the default authorization request resolver with one using properties for the BFF scheme, hostname and port
		  .authorizationRequestResolver(authorizationRequestResolver));

		// If SSL enabled, disable http (https only)
		if (Optional.ofNullable(serverProperties.getSsl()).map(Ssl::isEnabled).orElse(false)) {
			http.redirectToHttps();
		}

		// configure CORS from application properties
		http.cors().configurationSource(corsConfigurationSource);

		http.csrf(csrf -> csrf
		  // expose CSRF token to Javascript applications
		  .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
		  // Could not get CSRF work with Angular and new XorServerCsrfTokenRequestAttributeHandler (yet?)
		  // For now, hope that SameSite in CsrfCookieWebFilter below is enough and disable BREACH protection
		  // as per https://docs.spring.io/spring-security/reference/reactive/exploits/csrf.html#webflux-csrf-configure-request-handler
		  .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler()));
	    // @formatter:on

		return http.build();
	}

	@Component
	@Configuration
	public class CsrfCookieWebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			String key = CsrfToken.class.getName();
			Mono<CsrfToken> csrfToken = null != exchange.getAttribute(key) ? exchange.getAttribute(key) : Mono.empty();
			return csrfToken.doOnError(e -> {
				exchange.getResponse().getCookies().remove("XSRF-TOKEN");
			}).doOnSuccess(token -> {
				if (token == null) {
					exchange.getResponse().getCookies().remove("XSRF-TOKEN");
				} else {
					ResponseCookie cookie = ResponseCookie.from("XSRF-TOKEN", token.getToken()).maxAge(Duration.ofHours(1)).httpOnly(false).path("/")
							.sameSite(Cookie.SameSite.LAX.attributeValue()).build();
					exchange.getResponse().getCookies().add("XSRF-TOKEN", cookie);
				}
			}).then(chain.filter(exchange));
		}
	}

	// private static final String IDENTITIES_SESSION_ATTRIBUTE = "com.c4-soft.springaddons.user.identities";
	//
	// @Bean ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler() { return (WebFilterExchange webFilterExchange, Authentication
	// authentication) -> { if (authentication instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidcUser) { return
	// webFilterExchange.getExchange().getSession().flatMap(session -> {
	//
	// @SuppressWarnings("unchecked") final var identities = ((Map<String, UserIdentity>) session.getAttributes() .getOrDefault(IDENTITIES_SESSION_ATTRIBUTE,
	// new HashMap<String, UserIdentity>())); identities.put( oauth.getAuthorizedClientRegistrationId(), new
	// UserIdentity(oauth.getAuthorizedClientRegistrationId(), oidcUser.getSubject(), oidcUser.getIdToken().getTokenValue()));
	// session.getAttributes().put(IDENTITIES_SESSION_ATTRIBUTE, identities); return session.save(); }); } return Mono.empty().then(); };
	//
	// }
	//
	// @Data
	//
	// @RequiredArgsConstructor public static class UserIdentity implements Serializable { private static final long serialVersionUID = -6159688416636251073L;
	//
	// private final String registrationId; private final String subject; private final String idToken;
	//
	// }

}