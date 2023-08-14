package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientId;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsClientMultiTenancyEnabled;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsNotServlet;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcClientCondition;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@Conditional({ IsOidcClientCondition.class, IsNotServlet.class, IsClientMultiTenancyEnabled.class })
@AutoConfiguration
@PropertySource(value = "classpath:/c4-spring-addons.properties", ignoreResourceNotFound = true)
public class ReactiveSpringAddonsAop {

	@Aspect
	@Component
	@RequiredArgsConstructor
	public static class ReactiveAuthorizedClientAspect {
		private final Optional<AbstractReactiveAuthorizedSessionRepository> authorizedSessionRepository;
		private final ServerOAuth2AuthorizedClientRepository authorizedClientRepo;

		@Pointcut("within(org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository+) && execution(* *.saveAuthorizedClient(..))")
		public void saveAuthorizedClient() {
		}

		@Pointcut("within(org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository+) && execution(* *.removeAuthorizedClient(..))")
		public void removeAuthorizedClient() {
		}

		@Pointcut("within(org.springframework.security.web.server.authentication.logout.ServerLogoutHandler+) && execution(* *.logout(..))")
		public void logout() {
		}

		@AfterReturning("saveAuthorizedClient()")
		public void afterSaveAuthorizedClient(JoinPoint jp) {
			var authorizedClient = (OAuth2AuthorizedClient) jp.getArgs()[0];
			var exchange = (ServerWebExchange) jp.getArgs()[2];
			exchange.getSession().subscribe(session -> {
				final var registrationId = authorizedClient.getClientRegistration().getRegistrationId();
				final var name = authorizedClient.getPrincipalName();
				OAuth2PrincipalSupport.add(session, registrationId, name);
				this.authorizedSessionRepository.map(r -> r.save(new OAuth2AuthorizedClientId(registrationId, name), session.getId())).orElse(Mono.empty());
			});
		}

		@Before("removeAuthorizedClient()")
		public void beforeRemoveAuthorizedClient(JoinPoint jp) {
			var registrationId = (String) jp.getArgs()[0];
			var principal = (Authentication) jp.getArgs()[1];
			var exchange = (ServerWebExchange) jp.getArgs()[2];
			exchange.getSession().subscribe(session -> {
				OAuth2PrincipalSupport.add(session, registrationId, principal.getName());
				this.authorizedSessionRepository.map(r -> r.save(new OAuth2AuthorizedClientId(registrationId, principal.getName()), session.getId()))
						.orElse(Mono.empty());
			});
		}

		@Before("logout()")
		public void beforeServerLogoutHandlerLogout(JoinPoint jp) {
			var exchange = (WebFilterExchange) jp.getArgs()[0];
			var authentication = (Authentication) jp.getArgs()[1];
			if (authentication instanceof OAuth2AuthenticationToken oauth) {
				exchange.getExchange().getSession().subscribe(session -> {
					OAuth2PrincipalSupport.getName(session, oauth.getAuthorizedClientRegistrationId()).ifPresent(name -> {
						authorizedClientRepo
								.removeAuthorizedClient(oauth.getAuthorizedClientRegistrationId(), new StubAuthentication(name), exchange.getExchange())
								.subscribe();
					});
				});
			}
		}
	}

	static class OAuth2PrincipalSupport {
		private static final String OAUTH2_USERS_KEY = "com.c4-soft.spring-addons.oauth2.client.principal-by-issuer";

		public static Map<String, String> getNamesByIssuer(WebSession session) {
			return session.getAttributeOrDefault(OAUTH2_USERS_KEY, new HashMap<String, String>());
		}

		public static Optional<String> getName(WebSession session, String clientRegistrationId) {
			return Optional.ofNullable(getNamesByIssuer(session).get(clientRegistrationId));
		}

		public static synchronized void add(WebSession session, String clientRegistrationId, String principalName) {
			final var identities = getNamesByIssuer(session);
			identities.put(clientRegistrationId, principalName);
			session.getAttributes().put(OAUTH2_USERS_KEY, identities);
		}

		public static synchronized void remove(WebSession session, String clientRegistrationId) {
			final var identities = getNamesByIssuer(session);
			identities.remove(clientRegistrationId);
			session.getAttributes().put(OAUTH2_USERS_KEY, identities);
		}
	}

	@RequiredArgsConstructor
	static class StubAuthentication implements Authentication {
		private static final long serialVersionUID = -522103691400870102L;

		private final String name;

		@Override
		public String getName() {
			return name;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return List.of();
		}

		@Override
		public Object getCredentials() {
			return name;
		}

		@Override
		public Object getDetails() {
			return name;
		}

		@Override
		public Object getPrincipal() {
			return name;
		}

		@Override
		public boolean isAuthenticated() {
			return true;
		}

		@Override
		public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		}

	}
}
