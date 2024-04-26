package com.c4_soft.springaddons.rest;

import java.util.Optional;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;

@AutoConfiguration
public class SpringAddonsRestBeans {

	@ConditionalOnMissingBean
	@Bean
	BearerProvider bearerProvider() {
		return new DefaultBearerProvider();
	}

	@ConditionalOnWebApplication(type = Type.SERVLET)
	@Bean
	SpringAddonsRestClientSupport restClientSupport(
			SystemProxyProperties systemProxyProperties,
			SpringAddonsRestProperties restProperties,
			BearerProvider forwardingBearerProvider,
			Optional<OAuth2AuthorizedClientManager> authorizedClientManager) {
		return new SpringAddonsRestClientSupport(
				systemProxyProperties,
				restProperties,
				restProperties.getClient(),
				forwardingBearerProvider,
				authorizedClientManager);
	}

	@Conditional(IsServletWithWebClientCondition.class)
	@Bean
	SpringAddonsWebClientSupport webClientSupport(
			SystemProxyProperties systemProxyProperties,
			SpringAddonsRestProperties addonsProperties,
			BearerProvider forwardingBearerProvider,
			Optional<OAuth2AuthorizedClientManager> authorizedClientManager) {
		return new SpringAddonsWebClientSupport(systemProxyProperties, addonsProperties, forwardingBearerProvider, authorizedClientManager);
	}

	@ConditionalOnWebApplication(type = Type.REACTIVE)
	@Bean
	ReactiveSpringAddonsWebClientSupport reactiveWebClientSupport(
			SystemProxyProperties systemProxyProperties,
			SpringAddonsRestProperties addonsProperties,
			BearerProvider forwardingBearerProvider,
			Optional<ReactiveOAuth2AuthorizedClientManager> authorizedClientManager) {
		return new ReactiveSpringAddonsWebClientSupport(systemProxyProperties, addonsProperties, forwardingBearerProvider, authorizedClientManager);
	}
}
