package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.springframework.security.config.Customizer.withDefaults;

import java.net.URL;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.StreamSupport;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientId;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsNotServlet;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveSpringAddonsOidcBeans;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Flux;
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
 * This beans are defined only if "com.c4-soft.springaddons.oidc.client.back-channel-logout-enabled" property is true.
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Conditional(IsNotServlet.class)
@ConditionalOnProperty("com.c4-soft.springaddons.oidc.client.back-channel-logout-enabled")
@AutoConfiguration
@ImportAutoConfiguration(ReactiveSpringAddonsOidcBeans.class)
public class ReactiveSpringAddonsBackChannelLogoutBeans {

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
	SecurityWebFilterChain springAddonsBackChannelLogoutClientFilterChain(ServerHttpSecurity http, ServerProperties serverProperties) throws Exception {
		http.securityMatcher(new PathPatternParserServerWebExchangeMatcher(BACKCHANNEL_LOGOUT_PATH));
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
		private final AbstractReactiveAuthorizedSessionRepository authorizedSessionRepository;
		private final Map<String, IssuerData> issuersData = new ConcurrentHashMap<String, IssuerData>();
		private final ServerLogoutHandler logoutHandler;
		private final ReactiveClientRegistrationRepository clientRegistrationRepo;

		public BackChannelLogoutController(
				AbstractReactiveAuthorizedSessionRepository authorizedClientRepository,
				InMemoryReactiveClientRegistrationRepository registrationRepo,
				ServerLogoutHandler logoutHandler,
				ReactiveClientRegistrationRepository clientRegistrationRepo) {
			this.authorizedSessionRepository = authorizedClientRepository;
			this.logoutHandler = logoutHandler;
			this.clientRegistrationRepo = clientRegistrationRepo;
			StreamSupport.stream(registrationRepo.spliterator(), false)
					.filter(reg -> AuthorizationGrantType.AUTHORIZATION_CODE.equals(reg.getAuthorizationGrantType())).forEach(reg -> {
						final var issuer = reg.getProviderDetails().getIssuerUri();
						if (!this.issuersData.containsKey(issuer)) {
							this.issuersData.put(
									issuer,
									new IssuerData(
											issuer,
											new HashSet<>(),
											NimbusReactiveJwtDecoder.withJwkSetUri(reg.getProviderDetails().getJwkSetUri()).build()));
						}
						issuersData.get(issuer).clientRegistrationIds().add(reg.getRegistrationId());
					});
		}

		@PostMapping(path = BACKCHANNEL_LOGOUT_PATH, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
		public Mono<ResponseEntity<Void>> backChannelLogout(ServerWebExchange serverWebExchange) {
			serverWebExchange.getFormData().subscribe(body -> {
				final var tokenString = body.get("logout_token");
				if (tokenString == null || tokenString.size() != 1) {
					throw new BadLogoutRequestException();
				}
				issuersData.forEach((issuer, data) -> {
					data.jwtDecoder().decode(tokenString.get(0)).onErrorComplete().subscribe(jwt -> {
						final var isLogoutToken = Optional.ofNullable(jwt.getClaims().get("events")).map(Object::toString)
								.map(evt -> evt.contains("http://schemas.openid.net/event/backchannel-logout")).orElse(false);
						if (!isLogoutToken) {
							throw new BadLogoutRequestException();
						}
						final var logoutIss = Optional.ofNullable(jwt.getIssuer()).map(URL::toString).orElse(null);
						if (!Objects.equals(issuer, logoutIss)) {
							throw new BadLogoutRequestException();
						}
						for (var id : data.clientRegistrationIds()) {
							clientRegistrationRepo.findByRegistrationId(id).subscribe(reg -> {
								final var usernameClaim = reg.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
								final var principalName = jwt.getClaimAsString(usernameClaim);
								authorizedSessionRepository.delete(new OAuth2AuthorizedClientId(id, principalName)).subscribe(sessionId -> {
									authorizedSessionRepository.findAuthorizedClientIdsBySessionId(sessionId).collectList().subscribe(authorizedClientIds -> {
										if (authorizedClientIds.size() == 0) {
											logoutHandler.logout(null, null);
										}
									});
								});
							});
						}
					});
				});
			});
			return Mono.just(ResponseEntity.ok().build());
		}

		@ResponseStatus(HttpStatus.BAD_REQUEST)
		static final class BadLogoutRequestException extends RuntimeException {
			private static final long serialVersionUID = -1803794467531166681L;
		}
	}

	@Aspect
	@Component
	@RequiredArgsConstructor
	public static class ReactiveSessionRepositoryAspect implements SessionLifecycleEventNotifier {
		private static final Collection<ReactiveSessionListener> listeners = new ConcurrentLinkedQueue<>();

		@Override
		public void register(ReactiveSessionListener listener) {
			listeners.add(listener);
		}

		@Pointcut("within(org.springframework.session.ReactiveSessionRepository+) && execution(* *.createSession(..))")
		public void createSession() {
		}

		@Pointcut("within(org.springframework.session.ReactiveSessionRepository+) && execution(* *.deleteById(..))")
		public void deleteById() {
		}

		@AfterReturning(value = "createSession()", returning = "session")
		public void afterSessionCreated(Mono<WebSession> session) {
			session.flatMap(s -> Flux.fromIterable(listeners).doOnNext(l -> l.sessionCreated(s)).then(Mono.just(s))).subscribe();
		}

		@Before(value = "deleteById()")
		public void beforeDeleteById(JoinPoint jp) {
			var sessionId = (String) jp.getArgs()[0];
			listeners.forEach(l -> {
				l.sessionRemoved(sessionId);
			});
		}
	}

	@ConditionalOnMissingBean
	@Bean
	AbstractReactiveAuthorizedSessionRepository authorizedSessionRepository(SessionLifecycleEventNotifier sessionEventNotifier) {
		return new InMemoryReactiveAuthorizedSessionRepository(sessionEventNotifier);
	}

	private static record IssuerData(String issuer, Set<String> clientRegistrationIds, ReactiveJwtDecoder jwtDecoder) {
	}
}
