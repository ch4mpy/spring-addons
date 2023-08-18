package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.stream.Stream;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;

import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsClientMultiTenancyEnabled;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcClientCondition;

import lombok.RequiredArgsConstructor;

@ConditionalOnWebApplication(type = Type.SERVLET)
@Conditional({ IsOidcClientCondition.class, IsClientMultiTenancyEnabled.class })
@AutoConfiguration
@PropertySource(value = "classpath:/c4-spring-addons.properties", ignoreResourceNotFound = true)
public class SpringAddonsAop {

	@Aspect
	@Component
	@RequiredArgsConstructor
	public static class AuthorizedClientAspect {
		private final OAuth2AuthorizedClientRepository authorizedClientRepo;

		@Pointcut("within(org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository+) && execution(* *.loadAuthorizedClient(..))")
		public void loadAuthorizedClient() {
		}

		@Pointcut("within(org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository+) && execution(* *.saveAuthorizedClient(..))")
		public void saveAuthorizedClient() {
		}

		@Pointcut("within(org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository+) && execution(* *.removeAuthorizedClient(..))")
		public void removeAuthorizedClient() {
		}

		@Pointcut("within(org.springframework.security.web.authentication.logout.LogoutHandler+) && execution(* *.logout(..))")
		public void logout() {
		}

		@Around("loadAuthorizedClient()")
		public Object aroundLoadAuthorizedClient(ProceedingJoinPoint jp) throws Throwable {
			var clientRegistrationId = (String) jp.getArgs()[0];
			var principal = (Authentication) jp.getArgs()[1];
			var request = (jakarta.servlet.http.HttpServletRequest) jp.getArgs()[2];

			final var args = Stream.of(jp.getArgs()).toArray(Object[]::new);
			args[1] = MultiTenantOAuth2PrincipalSupport.getAuthentication(request.getSession(), clientRegistrationId).orElse(principal);

			return jp.proceed(args);
		}

		@AfterReturning("saveAuthorizedClient()")
		public void afterSaveAuthorizedClient(JoinPoint jp) {
			var authorizedClient = (OAuth2AuthorizedClient) jp.getArgs()[0];
			var principal = (Authentication) jp.getArgs()[1];
			var request = (jakarta.servlet.http.HttpServletRequest) jp.getArgs()[2];
			// var response = (jakarta.servlet.http.HttpServletResponse) jp.getArgs()[3];

			final var registrationId = authorizedClient.getClientRegistration().getRegistrationId();
			MultiTenantOAuth2PrincipalSupport.add(request.getSession(), registrationId, principal);

		}

		@Around("removeAuthorizedClient()")
		public Object aroundRemoveAuthorizedClient(ProceedingJoinPoint jp) throws Throwable {
			var clientRegistrationId = (String) jp.getArgs()[0];
			var principal = (Authentication) jp.getArgs()[1];
			var request = (jakarta.servlet.http.HttpServletRequest) jp.getArgs()[2];
			// var response = (jakarta.servlet.http.HttpServletResponse) jp.getArgs()[3];

			final var args = Stream.of(jp.getArgs()).toArray(Object[]::new);
			args[1] = MultiTenantOAuth2PrincipalSupport.getAuthentication(request.getSession(), clientRegistrationId).orElse(principal);

			MultiTenantOAuth2PrincipalSupport.remove(request.getSession(), clientRegistrationId);

			return jp.proceed(args);
		}

		@Before("logout()")
		public void beforeServerLogoutHandlerLogout(JoinPoint jp) {
			var request = (jakarta.servlet.http.HttpServletRequest) jp.getArgs()[0];
			var response = (jakarta.servlet.http.HttpServletResponse) jp.getArgs()[1];
			for (var e : MultiTenantOAuth2PrincipalSupport.getAuthenticationsByClientRegistrationId(request.getSession()).entrySet()) {
				authorizedClientRepo.removeAuthorizedClient(e.getKey(), e.getValue(), request, response);
			}
		}
	}
}
