package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxTestConf;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureWebTestClient
@ImportAutoConfiguration({ AddonsWebfluxTestConf.class })
class SampleApiIntegrationTests {
	@Autowired
	WebTestClient api;

	@Test
	@WithAnonymousUser
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@WithOpaqueToken("tonton-pirate.json")
	void givenUserIsTontonPirate_whenGetGreet_thenOk() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectBody(String.class).isEqualTo("Hello tonton-pirate! You are granted with [UNCLE, PIRATE].");
	}

	@Test
	@WithOpaqueToken("ch4mp.json")
	void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectBody(String.class)
				.isEqualTo("Hello ch4mp! You are granted with [NICE, AUTHOR, ROLE_AUTHORIZED_PERSONNEL].");
	}

}
