package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.stream.Stream;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

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
		private final ServerOAuth2AuthorizedClientRepository authorizedClientRepo;

		@Pointcut("within(org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository+) && execution(* *.loadAuthorizedClient(..))")
		public void loadAuthorizedClient() {
		}

		@Pointcut("within(org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository+) && execution(* *.saveAuthorizedClient(..))")
		public void saveAuthorizedClient() {
		}

		@Pointcut("within(org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository+) && execution(* *.removeAuthorizedClient(..))")
		public void removeAuthorizedClient() {
		}

		@Pointcut("within(org.springframework.security.web.server.authentication.logout.ServerLogoutHandler+) && execution(* *.logout(..))")
		public void logout() {
		}

		@SuppressWarnings("unchecked")
		@Around("loadAuthorizedClient()")
		public <T extends OAuth2AuthorizedClient> Mono<T> aroundLoadAuthorizedClient(ProceedingJoinPoint jp) throws Throwable {
			var clientRegistrationId = (String) jp.getArgs()[0];
			var principal = (Authentication) jp.getArgs()[1];
			var exchange = (ServerWebExchange) jp.getArgs()[2];

			final var args = Stream.of(jp.getArgs()).toArray(Object[]::new);

			return exchange.getSession().flatMap(session -> {
				args[1] = ReactiveMultiTenantOAuth2PrincipalSupport.getAuthentication(session, clientRegistrationId).orElse(principal);
				try {
					return (Mono<T>) jp.proceed(args);
				} catch (Throwable e) {
					return Mono.error(e);
				}
			});
		}

		@AfterReturning("saveAuthorizedClient()")
		public void afterSaveAuthorizedClient(JoinPoint jp) {
			var authorizedClient = (OAuth2AuthorizedClient) jp.getArgs()[0];
			var principal = (Authentication) jp.getArgs()[1];
			var exchange = (ServerWebExchange) jp.getArgs()[2];
			exchange.getSession().subscribe(session -> {
				final var registrationId = authorizedClient.getClientRegistration().getRegistrationId();
				ReactiveMultiTenantOAuth2PrincipalSupport.add(session, registrationId, principal);
			});
		}

		@SuppressWarnings("unchecked")
		@Around("removeAuthorizedClient()")
		public Mono<Void> aroundRemoveAuthorizedClient(ProceedingJoinPoint jp) {
			final var args = Stream.of(jp.getArgs()).toArray(Object[]::new);
			var clientRegistrationId = (String) args[0];
			var principal = (Authentication) args[1];
			var exchange = (ServerWebExchange) args[2];
			return exchange.getSession().flatMap(session -> {
				args[1] = ReactiveMultiTenantOAuth2PrincipalSupport.getAuthentication(session, clientRegistrationId).orElse(principal);
				try {
					return (Mono<Void>) jp.proceed(args);
				} catch (Throwable e) {
					return Mono.error(e);
				}
			});
		}

		@Before("logout()")
		public void beforeServerLogoutHandlerLogout(JoinPoint jp) {
			final var args = Stream.of(jp.getArgs()).toArray(Object[]::new);
			var exchange = (WebFilterExchange) args[0];

			exchange.getExchange().getSession().subscribe(session -> {
				ReactiveMultiTenantOAuth2PrincipalSupport.getAuthenticationsByClientRegistrationId(session).entrySet().forEach(e -> {
					authorizedClientRepo.removeAuthorizedClient(e.getKey(), e.getValue(), exchange.getExchange()).subscribe();
				});
			});
		}
	}
}
