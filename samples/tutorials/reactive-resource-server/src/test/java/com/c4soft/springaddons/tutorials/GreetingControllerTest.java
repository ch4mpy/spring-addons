package com.c4soft.springaddons.tutorials;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4soft.springaddons.tutorials.GreetingController.Message;

@WebFluxTest(controllers = GreetingController.class, properties = "server.ssl.enabled=false")
@Import({ WebSecurityConfig.class })
class GreetingControllerTest {

	@Autowired
	WebTestClient api;

	@Test
	void givenRequestIsNotAuthorized_whenGreet_thenUnauthorized() throws Exception {
		api.get().uri("/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	void givenUserAuthenticated_whenGetGreet_thenOk() throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockJwt()
				.authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR")))
			.get().uri("/greet").exchange()
			.expectStatus().isOk()
			.expectBody(Message.class).isEqualTo(new Message("Hi user! You are granted with: [NICE, AUTHOR]."));
		// @formatter:on
	}

	@Test
	void givenUserIsNice_whenGetRestricted_thenOk() throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockJwt()
				.authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR")))
			.get().uri("/restricted").exchange()
			.expectStatus().isOk()
			.expectBody(Message.class).isEqualTo(new Message("You are so nice!"));
		// @formatter:on
	}

	@Test
	void givenUserIsNotNice_whenGetRestricted_thenForbidden() throws Exception {
		// @formatter:off
		api.mutateWith(SecurityMockServerConfigurers.mockJwt()
				.authorities(new SimpleGrantedAuthority("AUTHOR")))
			.get().uri("/restricted").exchange()
			.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	void givenRequestIsNotAuthorized_whenGetRestricted_thenUnauthorized() throws Exception {
		api.get().uri("/restricted").exchange().expectStatus().isUnauthorized();
	}
}
