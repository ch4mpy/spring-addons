package com.c4_soft.springaddons.samples.web;

import static com.c4_soft.springaddons.security.oauth2.test.webflux.webtestclient.MockAuthenticationWebTestClientConfigurer.mockAuthentication;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.Collection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4_soft.springaddons.samples.conf.WebSecurityConfig;
import com.c4_soft.springaddons.security.oauth2.test.webflux.webtestclient.MockAuthenticationWebTestClientConfigurer;

import reactor.core.publisher.Mono;

@ExtendWith(SpringExtension.class)
@WebFluxTest(GreetingController.class)
@Import(WebSecurityConfig.class)
class GreetingControllerTestSpring {

	@Autowired
	WebTestClient client;

	@MockBean
	MessageService messageService;

	@MockBean
	ReactiveJwtDecoder reactiveJwtDecoder;

	@MockBean
	AuthoritiesConverter authoritiesConverter;

	@MockBean
	AuthenticationConverter authenticationConverter;

	@BeforeEach
	public void setup() {
		when(messageService.greet(any())).thenAnswer(invocation -> {
			final var auth = invocation.getArgument(0, Authentication.class);
			return Mono
					.just(String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities()));
		});
		when(messageService.getSecret()).thenReturn(Mono.just("Secret message"));
	}

	@Test
	void whenUserIsNotAuthenticatedThenGreetIsUnauthorized() {
		this.client.get().uri("/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	void whenUserIsAuthenticatedThenHeCanGetAGreeting() {
		authorizedClient("user", "ROLE_USER").get()
				.uri("/greet")
				.exchange()
				.expectBody(String.class)
				.consumeWith(resp -> {
					assertThat(resp.getResponseBody()).isEqualTo("Hello user! You are granted with [ROLE_USER].");
				});
	}

	@Test()
	void whenUserIsNotGrantedWithAuthorizedPersonelThenSecuredEndpointIsForbiden() {
		authorizedClient("user", "ROLE_USER").get().uri("/secured-endpoint").exchange().expectStatus().isForbidden();
	}

	@Test()
	void whenUserIsNotGrantedWithAuthorizedPersonelThenSecuredMethodIsForbiden() {
		authorizedClient("user").get().uri("/secured-method").exchange().expectStatus().isForbidden();
	}

	@Test()
	void whenUserIsGrantedWithAuthorizedPersonelThenSecuredEndpointIsAccessible() {
		authorizedClient("user", "ROLE_AUTHORIZED_PERSONNEL").get()
				.uri("/secured-endpoint")
				.exchange()
				.expectBody(String.class)
				.consumeWith(resp -> {
					assertThat(resp.getResponseBody()).isEqualTo("secret route");
				});
	}

	@Test()
	void whenUserIsGrantedWithAuthorizedPersonelThenSecuredMethodIsAccessible() {
		authorizedClient("user", "ROLE_AUTHORIZED_PERSONNEL").get()
				.uri("/secured-method")
				.exchange()
				.expectBody(String.class)
				.consumeWith(resp -> {
					assertThat(resp.getResponseBody()).isEqualTo("secret method");
				});
	}

	private WebTestClient authorizedClient(String username, String... roles) {
		return this.client.mutateWith(mockKeycloackAuth(username, roles));
	}

	private MockAuthenticationWebTestClientConfigurer<Authentication>
			mockKeycloackAuth(String username, String... roles) {
		return mockAuthentication(Authentication.class).name(username).authorities(roles);
	}

	static interface AuthoritiesConverter extends Converter<Jwt, Collection<GrantedAuthority>> {
	}

	static interface AuthenticationConverter extends Converter<Jwt, Mono<AbstractAuthenticationToken>> {
	}
}
