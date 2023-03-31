package com.c4soft.springaddons.tutorials;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;
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
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureWebTestClient
@Import(ReactiveClientApplicationTest.TestSecurityConf.class)
class ReactiveClientApplicationTest {
	static final AnonymousAuthenticationToken ANONYMOUS =
			new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Autowired
	WebTestClient webTestClient;

	@Test
	void givenRequestIsNotAuthorized_whenGetIndex_thenIsOk() throws Exception {
		webTestClient.get().uri("/").exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsAnonymous_whenGetIndex_thenIsOk() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS)).get().uri("/").exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsAuthenticated_whenGetIndex_thenIsOk() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockOidcLogin()).get().uri("/").exchange().expectStatus().isOk();
	}

	@Test
	void givenRequestIsNotAuthorized_whenGetLogin_thenIsOk() throws Exception {
		webTestClient.get().uri("/login").exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsAnonymous_whenGetLogin_thenIsOk() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS)).get().uri("/login").exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsAuthenticated_whenGetLogin_thenIsRedirected() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockOidcLogin()).get().uri("/login").exchange().expectStatus().is3xxRedirection();
	}

	@Test
	void givenRequestIsNotAuthorized_whenGetNice_thenIsRedirected() throws Exception {
		webTestClient.get().uri("/nice.html").exchange().expectStatus().is3xxRedirection();
	}

	@Test
	void givenUserIsAnonymous_whenGetNice_thenIsRedirected() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS)).get().uri("/nice.html").exchange().expectStatus()
				.is3xxRedirection();
	}

	@Test
	void givenUserIsNice_whenGetNice_thenIsOk() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockOidcLogin().authorities(new SimpleGrantedAuthority("NICE"))).get().uri("/nice.html")
				.exchange().expectStatus().isOk();
	}

	@Test
	void givenUserIsNotNice_whenGetNice_thenIsForbidden() throws Exception {
		webTestClient.mutateWith(SecurityMockServerConfigurers.mockOidcLogin()).get().uri("/nice.html").exchange().expectStatus().isForbidden();
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
