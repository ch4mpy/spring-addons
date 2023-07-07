package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxTestConf;

@SpringBootTest
@AutoConfigureWebTestClient
@ImportAutoConfiguration({ AddonsWebfluxTestConf.class })
@TestInstance(Lifecycle.PER_CLASS)
class WebfluxIntrospectingDefaultTest {
	@Autowired
	WebTestClient api;

	@Test
	void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@WithOpaqueToken("ch4mp.json")
	void givenUserIsCh4mp_whenGetGreet_thenOk() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectBody(String.class)
				.isEqualTo("Hello ch4mp! You are granted with [NICE, AUTHOR, ROLE_AUTHORIZED_PERSONNEL].");
	}

	@Test
	@WithOpaqueToken("tonton-pirate.json")
	void givenUserIsTontonPirate_whenGetGreet_thenOk() throws Exception {
		api.get().uri("https://localhost/greet").exchange().expectBody(String.class).isEqualTo("Hello tonton-pirate! You are granted with [UNCLE, PIRATE].");
	}

}
