package com.c4soft.springaddons.tutorials;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.OidcLoginMutator;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOidcLogin;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.OidcLoginAuthenticationSource;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureWebTestClient
@Import(ReactiveClientApplicationTest.TestSecurityConf.class)
class ReactiveClientApplicationTest {
	static final AnonymousAuthenticationToken ANONYMOUS =
			new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Autowired
	WebTestClient webTestClient;

	@Test
	void givenUserIsAnonymous_whenGetIndex_thenIsOk() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS)).get().uri("/").exchange().expectStatus().isOk();
	}

	@Test
	@WithAnonymousUser
	void givenUserIsAnonymousAnnotation_whenGetIndex_thenIsOk() throws Exception {
		webTestClient.get().uri("/").exchange().expectStatus().isOk();
	}

	@ParameterizedTest
	@MethodSource("identityMutators")
	void givenUserIsAuthenticated_whenGetIndex_thenIsOk(OidcLoginMutator identityMutator) throws Exception {
		// @formatter:off
		webTestClient.mutateWith(identityMutator)
			.get().uri("/").exchange()
			.expectStatus().isOk();
		// @formatter:on
	}

	static Stream<OidcLoginMutator> identityMutators() {
		Instant iat = Instant.now();
		Instant exp = iat.plusSeconds(42);
		return Stream.of(
				SecurityMockServerConfigurers.mockOidcLogin().oidcUser(
						new DefaultOidcUser(
								List.of(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR")),
								new OidcIdToken("test.token", iat, exp, Map.of(JwtClaimNames.SUB, "ch4mp")))),
				SecurityMockServerConfigurers.mockOidcLogin().oidcUser(
						new DefaultOidcUser(
								List.of(new SimpleGrantedAuthority("UNCLE"), new SimpleGrantedAuthority("SKIPPER")),
								new OidcIdToken("test.token", iat, exp, Map.of(JwtClaimNames.SUB, "tonton-pirate")))));
	}

	@ParameterizedTest
	@OidcLoginAuthenticationSource({
			@WithOidcLogin(
					authorities = { "NICE", "AUTHOR" },
					claims = @OpenIdClaims(usernameClaim = StandardClaimNames.PREFERRED_USERNAME, preferredUsername = "ch4mp")),
			@WithOidcLogin(
					authorities = { "UNCLE", "SKIPPER" },
					claims = @OpenIdClaims(usernameClaim = StandardClaimNames.PREFERRED_USERNAME, preferredUsername = "tonton-pirate")) })
	void givenUserIsAuthenticatedWithAnnotation_whenGetIndex_thenIsOk() throws Exception {
		webTestClient.get().uri("/").exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsAnonymous_whenGetLogin_thenIsOk() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS)).get().uri("/login").exchange().expectStatus().isOk();
	}

	@Test
	@WithAnonymousUser
	void givenUserIsAnonymousAnnotation_whenGetLogin_thenIsOk() throws Exception {
		webTestClient.get().uri("/login").exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsAuthenticated_whenGetLogin_thenIsRedirected() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockOidcLogin()).get().uri("/login").exchange().expectStatus().is3xxRedirection();
	}

	@Test
	@WithOidcLogin
	void givenUserIsAuthenticatedWithAnnotation_whenGetLogin_thenIsRedirected() throws Exception {
		webTestClient.get().uri("/login").exchange().expectStatus().is3xxRedirection();
	}

	@Test
	void givenUserIsAnonymous_whenGetNice_thenIsRedirected() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS)).get().uri("/nice.html").exchange().expectStatus()
				.is3xxRedirection();
	}

	@Test
	@WithAnonymousUser
	void givenUserIsAnonymousAnnotation_whenGetNice_thenIsRedirected() throws Exception {
		webTestClient.get().uri("/nice.html").exchange().expectStatus().is3xxRedirection();
	}

	@Test
	void givenUserIsNice_whenGetNice_thenIsOk() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockOidcLogin().authorities(new SimpleGrantedAuthority("NICE"))).get().uri("/nice.html")
				.exchange().expectStatus().isOk();
	}

	@Test
	@WithOidcLogin("NICE")
	void givenUserIsNiceAnnotation_whenGetNice_thenIsOk() throws Exception {
		webTestClient.get().uri("/nice.html").exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsNotNice_whenGetNice_thenIsForbidden() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockOidcLogin()).get().uri("/nice.html").exchange().expectStatus().isForbidden();
	}

	@Test
	@WithOidcLogin
	void givenUserIsNotNiceAnnotation_whenGetNice_thenIsForbidden() throws Exception {
		webTestClient.get().uri("/nice.html").exchange().expectStatus().isForbidden();
	}

	@TestConfiguration
	static class TestSecurityConf {
		@Bean
		InMemoryReactiveClientRegistrationRepository clientRegistrationRepository() {
			final var clientRegistrationRepository = mock(InMemoryReactiveClientRegistrationRepository.class);
			when(clientRegistrationRepository.iterator()).thenReturn(new ArrayList<ClientRegistration>().iterator());
			when(clientRegistrationRepository.spliterator()).thenReturn(new ArrayList<ClientRegistration>().spliterator());
			return clientRegistrationRepository;
		}
	}
}
