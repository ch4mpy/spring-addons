package com.c4_soft.springaddons.samples.resourceserver;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

/**
 * Full application context. {@link AddonsWebmvcTestConf} mocks the JWT decoding (the authorization
 * server is never called) and exposes {@link MockMvcSupport}; test annotations do the rest.
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration(AddonsWebmvcTestConf.class)
class ResourceServerApplicationTest {

  @Autowired
  MockMvcSupport api;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetMe_thenUnauthorized() throws Exception {
    api.get("/greetings/me").andExpect(status().isUnauthorized())
        // the auto-configured entry point lists the trusted issuers
        .andExpect(header().exists(HttpHeaders.WWW_AUTHENTICATE));
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenGetMe_thenOk() throws Exception {
    api.get("/greetings/me").andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("brice"));
  }

  @Test
  @WithAnonymousUser
  void givenOriginIsAllowed_whenPreflight_thenOk() throws Exception {
    api.perform(options("/greetings/me").header(HttpHeaders.ORIGIN, "http://localhost:4200")
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")).andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://localhost:4200"));
  }

  @Test
  @WithAnonymousUser
  void givenOriginIsNotAllowed_whenPreflight_thenForbidden() throws Exception {
    api.perform(options("/greetings/me").header(HttpHeaders.ORIGIN, "http://evil.com")
        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET")).andExpect(status().isForbidden());
  }
}
