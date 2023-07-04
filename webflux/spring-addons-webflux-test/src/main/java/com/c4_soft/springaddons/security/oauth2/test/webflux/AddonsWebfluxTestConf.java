package com.c4_soft.springaddons.security.oauth2.test.webflux;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

@TestConfiguration
@Import({ WebTestClientProperties.class, AuthenticationFactoriesTestConf.class })
public class AddonsWebfluxTestConf {

	@MockBean
	ReactiveJwtDecoder jwtDecoder;

	@MockBean
	ReactiveOpaqueTokenIntrospector introspector;

	@ConditionalOnMissingBean
	@Bean
	InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
		final var clientRegistrationRepository = mock(InMemoryReactiveClientRegistrationRepository.class);
		when(clientRegistrationRepository.iterator()).thenReturn(new ArrayList<ClientRegistration>().iterator());
		when(clientRegistrationRepository.spliterator()).thenReturn(new ArrayList<ClientRegistration>().spliterator());
		return clientRegistrationRepository;
	}

	@MockBean
	ReactiveOAuth2AuthorizedClientService oAuth2AuthorizedClientService;

	@Bean
	HttpSecurity httpSecurity() {
		return mock(HttpSecurity.class);
	}

	@Bean
	@Scope("prototype")
	WebTestClientSupport webTestClientSupport(
			WebTestClientProperties webTestClientProperties,
			WebTestClient webTestClient,
			SpringAddonsSecurityProperties addonsProperties) {
		return new WebTestClientSupport(webTestClientProperties, webTestClient, addonsProperties);
	}
}