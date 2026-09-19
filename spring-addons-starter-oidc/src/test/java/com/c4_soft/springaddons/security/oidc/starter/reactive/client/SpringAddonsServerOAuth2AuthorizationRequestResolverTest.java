package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.webflux.autoconfigure.WebFluxProperties;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

class SpringAddonsServerOAuth2AuthorizationRequestResolverTest {

	@Test
	void whenRequestPathMatchesAuthorizationCodePattern_thenClientRegistrationIdIsReturned() {
		final var actual = SpringAddonsServerOAuth2AuthorizationRequestResolver.resolveRegistrationId("/oauth2/authorization/authorization-code");
		assertEquals("authorization-code", actual);
	}

	@Test
	void whenRequestPathDoesNotMatchAuthorizationCodePattern_thenClientRegistrationIdIsReturned() {
		final var actual = SpringAddonsServerOAuth2AuthorizationRequestResolver.resolveRegistrationId("/login/authorization/authorization-code");
		assertNull(actual);
	}

	@Test
	void givenNoClientUri_whenResolve_thenRedirectUriResolvedBySpringSecurityIsKept() {
		final var resolver = resolver(new SpringAddonsOidcClientProperties());
		final var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost:8080/oauth2/authorization/reg"));

		final var actual = resolver.resolve(exchange).block();

		assertThat(actual).isNotNull();
		assertThat(actual.getRedirectUri()).isEqualTo("http://localhost:8080/login/oauth2/code/reg");
	}

	@Test
	void givenClientUri_whenResolve_thenRedirectUriIsRebasedOnClientUri() {
		final var properties = new SpringAddonsOidcClientProperties();
		properties.setClientUri(Optional.of(URI.create("https://bff.example.com/bff")));
		final var resolver = resolver(properties);
		final var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost:8080/oauth2/authorization/reg"));

		final var actual = resolver.resolve(exchange).block();

		assertThat(actual).isNotNull();
		assertThat(actual.getRedirectUri()).isEqualTo("https://bff.example.com/bff/login/oauth2/code/reg");
	}

	@Test
	void givenUnknownRegistrationId_whenResolve_thenEmpty() {
		final var resolver = resolver(new SpringAddonsOidcClientProperties());
		final var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost:8080/oauth2/authorization/unknown"));

		assertThat(resolver.resolve(exchange).blockOptional()).isEmpty();
	}

	private static SpringAddonsServerOAuth2AuthorizationRequestResolver resolver(SpringAddonsOidcClientProperties addonsClientProperties) {
		final var bootClientProperties = new OAuth2ClientProperties();
		bootClientProperties.getRegistration().put("reg", new OAuth2ClientProperties.Registration());
		final var clientRegistrationRepository = new InMemoryReactiveClientRegistrationRepository(
				ClientRegistration
						.withRegistrationId("reg")
						.clientId("client-id")
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
						.authorizationUri("https://op/authorize")
						.tokenUri("https://op/token")
						.build());
		return new SpringAddonsServerOAuth2AuthorizationRequestResolver(bootClientProperties, clientRegistrationRepository, addonsClientProperties,
				new WebFluxProperties());
	}

}
