package com.c4_soft.springaddons.security.oauth2.config.reactive;

import static org.springframework.security.config.Customizer.withDefaults;

import java.net.URL;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;

import reactor.core.publisher.Mono;

/**
 * <p>
 * This provides with a client side implementation of the OIDC <a href= "https://openid.net/specs/openid-connect-backchannel-1_0.html">Back-Channel Logout</a>
 * specification. Keycloak conforms to this OP side of the spec.
 * <a href= "https://community.auth0.com/t/openid-back-channel-logout-implementation/100112/8">Auth0</a> could some day.
 * </p>
 * <p>
 * Implementation is made with a security filter-chain intercepting just the "/backchannel_logout" route and a controller handling requests to that end-point.
 * </p>
 * <p>
 * This beans are defined only if "com.c4-soft.springaddons.security.client.back-channel-logout-enabled" property is true.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnProperty("com.c4-soft.springaddons.security.client.back-channel-logout-enabled")
@AutoConfiguration
@Import({ SpringAddonsOAuth2ClientProperties.class })
public class SpringAddonsBackChannelLogoutBeans {

	/**
	 * Requests from the OP are anonymous, are not part of a session, and have no CSRF token. It contains a logout JWT which serves both to authenticate the
	 * request and protect against CSRF.
	 *
	 * @param  http
	 * @param  serverProperties Spring Boot server properties
	 * @return                  a security filter-chain dedicated to back-channel logout handling
	 * @throws Exception
	 */
	@Order(Ordered.HIGHEST_PRECEDENCE)
	@Bean
	SecurityWebFilterChain springAddonsBackChannelLogoutClientFilterChain(ServerHttpSecurity http, ServerProperties serverProperties) throws Exception {
		http.securityMatcher(new PathPatternParserServerWebExchangeMatcher("/backchannel_logout"));
		http.authorizeExchange(exchange -> exchange.anyExchange().permitAll());
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.redirectToHttps(withDefaults());
		}
		http.cors(cors -> cors.disable());
		http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
		http.csrf(csrf -> csrf.disable());
		return http.build();
	}

	/**
	 * <p>
	 * Handles a POST request containing a JWT logout token provided as application/x-www-form-urlencoded as specified in
	 * <a href= "https://openid.net/specs/openid-connect-backchannel-1_0.html">Back-Channel Logout</a> specification.
	 * </p>
	 * <p>
	 * This end-point will:
	 * <ul>
	 * <li>remove the relevant authorized client (based on issuer URI) for the relevant user (based on the subject)</li>
	 * <li>maybe invalidate user session: only if the removed authorized client was the last one the user had</li>
	 * </ul>
	 *
	 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	@Component
	@RestController
	public static class BackChannelLogoutController {
		private final SpringAddonsServerOAuth2AuthorizedClientRepository authorizedClientRepository;
		private final Map<String, ReactiveJwtDecoder> jwtDecoders;

		public BackChannelLogoutController(
				SpringAddonsServerOAuth2AuthorizedClientRepository authorizedClientRepository,
				InMemoryReactiveClientRegistrationRepository registrationRepo) {
			this.authorizedClientRepository = authorizedClientRepository;
			this.jwtDecoders = StreamSupport.stream(registrationRepo.spliterator(), false)
					.filter(reg -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(reg.getAuthorizationGrantType()))
					.map(ClientRegistration::getProviderDetails).collect(
							Collectors.toMap(
									provider -> provider.getIssuerUri(),
									provider -> NimbusReactiveJwtDecoder.withJwkSetUri(provider.getJwkSetUri()).build()));
		}

		@PostMapping(path = "/backchannel_logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
		public Mono<ResponseEntity<Void>> backChannelLogout(ServerWebExchange serverWebExchange) {
			return serverWebExchange.getFormData().map(body -> {
				final var tokenString = body.get("logout_token");
				if (tokenString == null || tokenString.size() != 1) {
					throw new BadLogoutRequestException();
				}
				jwtDecoders.forEach((issuer, decoder) -> {
					decoder.decode(tokenString.get(0)).onErrorComplete().subscribe(jwt -> {
						final var isLogoutToken = Optional.ofNullable(jwt.getClaims().get("events")).map(Object::toString)
								.map(evt -> evt.contains("http://schemas.openid.net/event/backchannel-logout")).orElse(false);
						if (!isLogoutToken) {
							throw new BadLogoutRequestException();
						}
						final var logoutIss = Optional.ofNullable(jwt.getIssuer()).map(URL::toString).orElse(null);
						if (!Objects.equals(issuer, logoutIss)) {
							throw new BadLogoutRequestException();
						}
						final var logoutSub = jwt.getSubject();
						authorizedClientRepository.removeAuthorizedClients(logoutIss, logoutSub).subscribe(s -> {
							s.invalidate();
						});
					});
				});
				return ResponseEntity.ok().build();
			});
		}

		@ResponseStatus(HttpStatus.BAD_REQUEST)
		static final class BadLogoutRequestException extends RuntimeException {
			private static final long serialVersionUID = -1803794467531166681L;
		}
	}

}
