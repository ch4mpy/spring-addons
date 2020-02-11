package com.c4_soft.springaddons.test.security.web.reactive.server.keycloak;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import com.c4_soft.springaddons.test.security.fixtures.GreetingApp.GreetingController;
import com.c4_soft.springaddons.test.security.fixtures.MessageServiceImpl;

@RunWith(SpringRunner.class)
public class ReactiveKeycloakAuthWebTestClientConfigurerTest extends ReactiveKeycloakAuthUnitTestingSupport {
	private final GreetingController controller = new GreetingController(new MessageServiceImpl());

	private KeycloakAuthWebTestClientConfigurer mockCh4mpy() {
		return authentication().name("ch4mpy").roles("AUTHORIZED_PERSONNEL");
	}

//@formatter:off
	@Test
	public void testDefaultAccessTokenConfigurer() {
		webTestClient(controller).with(authentication()).get("/greet").expectBody(String.class)
				.isEqualTo("Hello user! You are granted with [ROLE_offline_access, ROLE_uma_authorization].");
	}

	@Test
	public void testCustomAccessTokenConfigurer() {
		webTestClient(controller).with(mockCh4mpy()).get("/greet").expectBody(String.class)
				.isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}
//@formatter:on
}
