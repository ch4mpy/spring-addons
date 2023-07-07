package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.net.URL;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.security.oidc.starter.synchronised.SpringAddonsOidcBeans;

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
 * This beans are defined only if "com.c4-soft.springaddons.oidc.client.back-channel-logout-enabled" property is true.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnWebApplication(type = Type.SERVLET)
@ConditionalOnProperty("com.c4-soft.springaddons.oidc.client.back-channel-logout-enabled")
@AutoConfiguration
@ImportAutoConfiguration(SpringAddonsOidcBeans.class)
public class SpringAddonsBackChannelLogoutBeans {

	private static final String BACKCHANNEL_LOGOUT_PATH = "/backchannel_logout";

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
	SecurityFilterChain springAddonsBackChannelLogoutClientFilterChain(HttpSecurity http, ServerProperties serverProperties) throws Exception {
		http.securityMatcher(new AntPathRequestMatcher(BACKCHANNEL_LOGOUT_PATH));
		http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests.anyRequest().permitAll());
		if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
			http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
		}
		http.cors(cors -> cors.disable());
		http.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
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
		private final SpringAddonsOAuth2AuthorizedClientRepository authorizedClientRepository;
		private final Map<String, JwtDecoder> jwtDecoders;

		public BackChannelLogoutController(
				SpringAddonsOAuth2AuthorizedClientRepository authorizedClientRepository,
				InMemoryClientRegistrationRepository registrationRepo) {
			this.authorizedClientRepository = authorizedClientRepository;
			this.jwtDecoders = StreamSupport.stream(registrationRepo.spliterator(), false)
					.filter(reg -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(reg.getAuthorizationGrantType()))
					.map(ClientRegistration::getProviderDetails).collect(
							Collectors.toMap(provider -> provider.getIssuerUri(), provider -> NimbusJwtDecoder.withJwkSetUri(provider.getJwkSetUri()).build()));
		}

		@PostMapping(path = BACKCHANNEL_LOGOUT_PATH, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
		public ResponseEntity<Void> backChannelLogout(@RequestParam MultiValueMap<String, String> body) {
			final var tokenString = body.get("logout_token");
			if (tokenString == null || tokenString.size() != 1) {
				throw new BadLogoutRequestException();
			}
			jwtDecoders.forEach((issuer, decoder) -> {
				try {
					final var jwt = decoder.decode(tokenString.get(0));
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
					final var sessionsToInvalidate = authorizedClientRepository.removeAuthorizedClients(logoutIss, logoutSub);
					sessionsToInvalidate.forEach(s -> {
						s.invalidate();
					});
				} catch (JwtException e) {
				}
			});
			return ResponseEntity.ok().build();
		}

		@ResponseStatus(HttpStatus.BAD_REQUEST)
		static final class BadLogoutRequestException extends RuntimeException {
			private static final long serialVersionUID = -8703279699142477824L;
		}
	}

}
