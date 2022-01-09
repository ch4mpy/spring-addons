package com.c4_soft.springaddons.tests.webflux;

import static com.c4_soft.springaddons.security.oauth2.test.webflux.OidcIdAuthenticationTokenWebTestClientConfigurer.oidcId;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.samples.webflux.OidcIdAuthenticationTokenReactiveApp;
import com.c4_soft.springaddons.samples.webflux.domain.MessageService;
import com.c4_soft.springaddons.samples.webflux.web.GreetingController;
import com.c4_soft.springaddons.security.oauth2.test.webflux.JwtTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;

import reactor.core.publisher.Mono;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { GreetingController.class, OidcIdAuthenticationTokenReactiveApp.WebSecurityConfig.class })
@WebFluxTest(GreetingController.class)
@Import({ JwtTestConf.class, WebTestClientSupport.class })
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
			final Authentication auth = invocation.getArgument(0, Authentication.class);
			return Mono.just(String.format("Hello %s! You are granted with %s.", auth.getName(), auth.getAuthorities()));
		});
	}

	//@formatter:off
	@Test
	public void testDefaultAccessTokenConfigurer() {
		client.mutateWith(oidcId()).get("https://localhost/greet").expectBody(String.class)
				.isEqualTo("Hello user! You are granted with [ROLE_USER].");
	}

	@Test
	public void testCustomAccessTokenConfigurer() {
		asCh4mpy().get("https://localhost/greet").expectBody(String.class)
				.isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}
	//@formatter:on

	private WebTestClientSupport asCh4mpy() {
		return client.mutateWith(oidcId().token(oidcId -> oidcId.subject("ch4mpy").preferredUsername("ch4mpy")).authorities("ROLE_AUTHORIZED_PERSONNEL"));
	}
}
