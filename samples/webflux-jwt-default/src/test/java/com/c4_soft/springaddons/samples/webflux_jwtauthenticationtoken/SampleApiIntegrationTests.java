package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webtestclient.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.reactive.server.WebTestClient;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxTestConf;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@Import({AddonsWebfluxTestConf.class})
@TestInstance(Lifecycle.PER_CLASS)
class SampleApiIntegrationTests {
  @Autowired
  WebTestClient api;

  @Test
  void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
    api.get().uri("/greet").exchange().expectStatus().isUnauthorized();
  }

  @Test
  @WithJwt("ch4mp.json")
  void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
    // @formatter:off
		api.get().uri("/greet").exchange()
			.expectStatus().isOk()
			.expectBody(String.class).isEqualTo("Hello ch4mp! You are granted with [USER_ROLES_EDITOR, ROLE_AUTHORIZED_PERSONNEL].");
		// @formatter:on
  }

}
