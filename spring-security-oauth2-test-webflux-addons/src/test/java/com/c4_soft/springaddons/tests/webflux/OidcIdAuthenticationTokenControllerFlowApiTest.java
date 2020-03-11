package com.c4_soft.springaddons.tests.webflux;

import static com.c4_soft.springaddons.security.oauth2.test.webflux.webtestclient.OidcIdAuthenticationTokenWebTestClientConfigurer.oidcIdAuthenticationToken;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.samples.webflux.OidcIdAuthenticationTokenReactiveApp;
import com.c4_soft.springaddons.samples.webflux.domain.GreetingController;
import com.c4_soft.springaddons.samples.webflux.domain.MessageService;
import com.c4_soft.springaddons.security.oauth2.test.webflux.webtestclient.WebTestClientSupport;

import reactor.core.publisher.Mono;

@RunWith(SpringRunner.class)
@ContextConfiguration(
		classes = {
				GreetingController.class,
				OidcIdAuthenticationTokenReactiveApp.ReactiveJwtSecurityConfig.class,
				WebTestClientSupport.class })
@WebFluxTest(GreetingController.class)
public class OidcIdAuthenticationTokenControllerFlowApiTest {
	@MockBean
	MessageService messageService;

	@Autowired
	WebTestClientSupport client;

	@MockBean
	ReactiveJwtDecoder reactiveJwtDecoder;

	@Before
	public void setUp() {
		when(messageService.greet(any(Authentication.class))).thenAnswer(invocation -> {
			final var auth = invocation.getArgument(0, Authentication.class);
			return Mono
					.just(String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities()));
		});
	}

	private WebTestClientSupport asCh4mpy() {
		return client.mutateWith(
				oidcIdAuthenticationToken().token(oidcId -> oidcId.preferredUsername("ch4mpy"))
						.authorities("ROLE_AUTHORIZED_PERSONNEL"));
	}

	//@formatter:off
	@Test
	public void testDefaultAccessTokenConfigurer() {
		client.mutateWith(oidcIdAuthenticationToken()).get("/greet").expectBody(String.class)
				.isEqualTo("Hello user! You are granted with [ROLE_USER].");
	}

	@Test
	public void testCustomAccessTokenConfigurer() {
		asCh4mpy().get("/greet").expectBody(String.class)
				.isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}
	//@formatter:on
}
