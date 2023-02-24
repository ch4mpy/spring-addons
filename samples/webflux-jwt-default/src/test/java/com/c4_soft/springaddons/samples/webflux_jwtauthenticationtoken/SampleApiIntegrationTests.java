package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxTestConf;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureWebTestClient
@ImportAutoConfiguration({ AddonsWebfluxTestConf.class })
class SampleApiIntegrationTests {
	@Autowired
	WebTestClient api;

	@Test
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@WithMockJwtAuth()
	void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectBody(String.class).isEqualTo("Hello user! You are granted with [].");
	}

	@Test
	@WithMockJwtAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(preferredUsername = "Ch4mpy"))
	void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectBody(String.class)
				.isEqualTo("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
	}

}
