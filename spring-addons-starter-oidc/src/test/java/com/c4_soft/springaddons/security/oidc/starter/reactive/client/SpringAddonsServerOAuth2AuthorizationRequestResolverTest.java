package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.web.reactive.WebFluxProperties;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import com.c4_soft.springaddons.security.oidc.starter.properties.InvalidPostLoginUriException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

class SpringAddonsServerOAuth2AuthorizationRequestResolverTest {

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

	@Test
	void givenAllowedPostLoginUris_whenResolve_thenBothStoredInSession() {
		final var resolver = resolver(new SpringAddonsOidcClientProperties());
		final var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost:8080/oauth2/authorization/reg")
				.header(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER, "/ui/account")
				.queryParam(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_PARAM, "/ui/error"));

		assertThat(resolver.resolve(exchange).block()).isNotNull();

		final var session = exchange.getSession().block();
		assertThat(session.getAttributes())
				.containsEntry(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_SESSION_ATTRIBUTE, "/ui/account")
				.containsEntry(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_SESSION_ATTRIBUTE, "/ui/error");
	}

	@Test
	void givenPostLoginSuccessUriIsNotAllowed_whenResolve_thenErrorAndSessionUntouched() {
		final var resolver = resolver(new SpringAddonsOidcClientProperties());
		final var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost:8080/oauth2/authorization/reg")
				.header(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER, "https://evil.com/ui/account"));

		assertThatThrownBy(() -> resolver.resolve(exchange).block()).isInstanceOf(InvalidPostLoginUriException.class);

		final var session = exchange.getSession().block();
		assertThat(session.isStarted()).isFalse();
		assertThat(session.getAttributes()).isEmpty();
	}

	@Test
	void givenAllowedSuccessUriAndRefusedFailureUri_whenResolve_thenErrorAndSuccessUriNotStored() {
		final var resolver = resolver(new SpringAddonsOidcClientProperties());
		final var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost:8080/oauth2/authorization/reg")
				.header(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_SUCCESS_URI_HEADER, "/ui/account")
				.header(SpringAddonsOidcClientProperties.POST_AUTHENTICATION_FAILURE_URI_HEADER, "//evil.com/ui/error"));

		assertThatThrownBy(() -> resolver.resolve(exchange).block()).isInstanceOf(InvalidPostLoginUriException.class);

		final var session = exchange.getSession().block();
		assertThat(session.isStarted()).isFalse();
		assertThat(session.getAttributes()).isEmpty();
	}

	@Test
	void givenNoPostLoginUri_whenResolve_thenSessionNotStarted() {
		final var resolver = resolver(new SpringAddonsOidcClientProperties());
		final var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost:8080/oauth2/authorization/reg"));

		assertThat(resolver.resolve(exchange).block()).isNotNull();

		assertThat(exchange.getSession().block().isStarted()).isFalse();
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
