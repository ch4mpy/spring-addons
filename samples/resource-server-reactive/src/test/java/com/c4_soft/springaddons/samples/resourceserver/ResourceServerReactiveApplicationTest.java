package com.c4_soft.springaddons.samples.resourceserver;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;

/**
 * Full application context. {@link AddonsWebfluxTestConf} mocks the JWT decoding (the authorization
 * server is never called) and exposes {@link WebTestClientSupport}; test annotations do the rest.
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureWebTestClient
@ImportAutoConfiguration(AddonsWebfluxTestConf.class)
class ResourceServerReactiveApplicationTest {

  @Autowired
  WebTestClientSupport api;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetMe_thenUnauthorized() {
    api.get("/greetings/me").expectStatus().isUnauthorized()
        // the auto-configured entry point lists the trusted issuers
        .expectHeader().exists(HttpHeaders.WWW_AUTHENTICATE);
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenGetMe_thenOk() {
    api.get("/greetings/me").expectStatus().isOk().expectBody().jsonPath("$.username")
        .isEqualTo("brice");
  }
}
