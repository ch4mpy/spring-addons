package com.c4_soft.dzone_oauth2_spring.c4_bff;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.stereotype.Component;

import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.reactive.client.SpringAddonsServerLogoutSuccessHandler;

import reactor.core.publisher.Mono;

@Configuration
public class SecurityConf {

	@Component
	static class AngularLogoutSucessHandler implements ServerLogoutSuccessHandler {
		private final SpringAddonsServerLogoutSuccessHandler delegate;

		public AngularLogoutSucessHandler(LogoutRequestUriBuilder logoutUriBuilder, ReactiveClientRegistrationRepository clientRegistrationRepo) {
			this.delegate = new SpringAddonsServerLogoutSuccessHandler(logoutUriBuilder, clientRegistrationRepo);
		}

		@Override
		public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
			return delegate.onLogoutSuccess(exchange, authentication).then(Mono.fromRunnable(() -> {
				exchange.getExchange().getResponse().setStatusCode(HttpStatus.ACCEPTED);
			}));
		}

	}
}
