package com.c4soft.springaddons.samples.bff.gateway;

import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.server.Cookie;
import org.springframework.boot.web.server.Ssl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.ResponseCookie;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import reactor.core.publisher.Mono;

@Configuration
public class WebSecurityConfig {

	@Order(Ordered.HIGHEST_PRECEDENCE)
	@Bean
	SecurityWebFilterChain clientFilterChain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			@Value("${gateway-uri}") URI gatewayUri,
			ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
			SpringAddonsSecurityProperties addonsProperties)
			throws Exception {

		final var isSsl = Optional.ofNullable(serverProperties.getSsl()).map(Ssl::isEnabled).orElse(false);

		// @formatter:off

	    // securityMatcher is restricted to UI resources and we want all to be accessible to anonymous
	    http.authorizeExchange().pathMatchers("/", "/login/**", "/oauth2/**", "/ui/**").permitAll()
	    	.anyExchange().authenticated();

	    http.exceptionHandling(exceptionHandling -> exceptionHandling
				.authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/login")))
	    .oauth2Login(oauth2 -> oauth2
	    		.authorizationRequestResolver(authorizationRequestResolver));

	    // @formatter:on

		// If SSL enabled, disable http (https only)
		if (isSsl) {
			http.redirectToHttps();
		}

		http.cors().configurationSource(corsConfigurationSource(addonsProperties));

		http.csrf(
				csrf -> csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
						.csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler()));

		return http.build();
	}

	@Bean
	ReactiveOAuth2UserService<OidcUserRequest, OidcUser>
			oidcUserService(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
		return (userRequest) -> {
			return Mono.just(
					new DefaultOidcUser(
							authoritiesConverter.convert(userRequest.getIdToken().getClaims()),
							userRequest.getIdToken(),
							new OidcUserInfo(userRequest.getIdToken().getClaims())));
		};
	}

	@Component
	@Configuration
	public class CsrfCookieWebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			String key = CsrfToken.class.getName();
			Mono<CsrfToken> csrfToken = null != exchange.getAttribute(key) ? exchange.getAttribute(key) : Mono.empty();
			return csrfToken.doOnSuccess(token -> {
				ResponseCookie cookie = ResponseCookie.from("XSRF-TOKEN", token.getToken()).maxAge(Duration.ofHours(1)).httpOnly(false).path("/")
						.sameSite(Cookie.SameSite.LAX.attributeValue()).build();
				exchange.getResponse().getCookies().add("XSRF-TOKEN", cookie);
			}).then(chain.filter(exchange));
		}
	}

	private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties addonsProperties) {
		final var source = new UrlBasedCorsConfigurationSource();
		for (final var corsProps : addonsProperties.getCors()) {
			final var configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
			configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
			configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
			configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
			source.registerCorsConfiguration(corsProps.getPath(), configuration);
		}
		return source;
	}

	/*
	 * private static final String IDENTITIES_SESSION_ATTRIBUTE = "com.c4-soft.springaddons.user.identities";
	 *
	 * @Bean ServerAuthenticationSuccessHandler serverAuthenticationSuccessHandler() { return (WebFilterExchange webFilterExchange, Authentication
	 * authentication) -> { if (authentication instanceof OAuth2AuthenticationToken oauth && oauth.getPrincipal() instanceof OidcUser oidcUser) { return
	 * webFilterExchange.getExchange().getSession().flatMap(session -> {
	 *
	 * @SuppressWarnings("unchecked") final var identities = ((Map<String, UserIdentity>) session.getAttributes() .getOrDefault(IDENTITIES_SESSION_ATTRIBUTE,
	 * new HashMap<String, UserIdentity>())); identities.put( oauth.getAuthorizedClientRegistrationId(), new
	 * UserIdentity(oauth.getAuthorizedClientRegistrationId(), oidcUser.getSubject(), oidcUser.getIdToken().getTokenValue()));
	 * session.getAttributes().put(IDENTITIES_SESSION_ATTRIBUTE, identities); return session.save(); }); } return Mono.empty().then(); };
	 *
	 * }
	 *
	 * @Data
	 *
	 * @RequiredArgsConstructor public static class UserIdentity implements Serializable { private static final long serialVersionUID = -6159688416636251073L;
	 *
	 * private final String registrationId; private final String subject; private final String idToken;
	 *
	 * }
	 */
}