package com.c4_soft.springaddons.security.oauth2.test.webflux;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import java.util.ArrayList;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oauth2.test.AuthenticationFactoriesTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsNotServlet;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcResourceServerCondition;
import reactor.core.publisher.Mono;

@Conditional({ IsOidcResourceServerCondition.class, IsNotServlet.class })
@AutoConfiguration
@ImportAutoConfiguration(classes = { WebTestClientProperties.class, AuthenticationFactoriesTestConf.class }, exclude = { AddonsWebmvcTestConf.class })
public class AddonsWebfluxTestConf {

	@MockitoBean
	ReactiveJwtDecoder jwtDecoder;

	@MockitoBean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> reactiveAuthenticationManagerResolver;

	@MockitoBean
	ReactiveOpaqueTokenIntrospector introspector;

	@ConditionalOnMissingBean
	@Bean
	InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
		final var clientRegistrationRepository = mock(InMemoryReactiveClientRegistrationRepository.class);
		when(clientRegistrationRepository.iterator()).thenReturn(new ArrayList<ClientRegistration>().iterator());
		when(clientRegistrationRepository.spliterator()).thenReturn(new ArrayList<ClientRegistration>().spliterator());
		when(clientRegistrationRepository.findByRegistrationId(anyString()))
				.thenAnswer(
						invocation -> Mono
								.just(
										ClientRegistration
												.withRegistrationId(invocation.getArgument(0))
												.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
												.clientId(invocation.getArgument(0))
												.redirectUri("http://localhost:8080/oauth2/code/%s".formatted(invocation.getArgument(0).toString()))
												.authorizationUri("https://localhost:8443/auth")
												.tokenUri("https://localhost:8443/token")
												.build()));
		return clientRegistrationRepository;
	}

	@MockitoBean
	ReactiveOAuth2AuthorizedClientService oAuth2AuthorizedClientService;

	@Bean
	@Scope("prototype")
	WebTestClientSupport
			webTestClientSupport(WebTestClientProperties webTestClientProperties, WebTestClient webTestClient, SpringAddonsOidcProperties addonsProperties) {
		return new WebTestClientSupport(webTestClientProperties, webTestClient, addonsProperties);
	}
}