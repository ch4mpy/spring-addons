package com.c4_soft.springaddons.samples.restclient;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.wiremock.spring.ConfigureWireMock;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.AuthenticationFactoriesTestConf;
import com.github.tomakehurst.wiremock.WireMockServer;

/**
 * <p>
 * Both consumed APIs and the Keycloak token endpoint are stubbed by WireMock (mappings in
 * {@code src/test/resources/wiremock/keycloak}). What is asserted here is not the controller logic
 * but what the auto-configured REST clients actually put on the wire: which {@code Authorization}
 * header reaches each API.
 * </p>
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
// only the factories behind @WithJwt: unlike AddonsWebmvcTestConf, this leaves the real
// ClientRegistrationRepository in place, which the client_credentials flow below needs
@ImportAutoConfiguration(AuthenticationFactoriesTestConf.class)
@EnableWireMock(@ConfigureWireMock(name = "keycloak", port = 8090,
    filesUnderClasspath = "wiremock/keycloak"))
class RestClientApplicationTest {

  @Autowired
  MockMvc api;

  @InjectWireMock("keycloak")
  WireMockServer wireMock;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetRelayedGreeting_thenUnauthorized() throws Exception {
    api.perform(get("/relayed-greeting")).andExpect(status().isUnauthorized());
  }

  /**
   * {@code forward-bearer: true}: the token which authorized the incoming request is put on the
   * outgoing one. The WireMock stub answers only when it receives exactly that Bearer.
   */
  @Test
  @WithJwt(file = "brice.json", bearerString = "brice-access-token")
  void givenUserIsBrice_whenGetRelayedGreeting_thenIncomingTokenIsForwarded() throws Exception {
    api.perform(get("/relayed-greeting")).andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("brice"));

    wireMock.verify(getRequestedFor(urlPathEqualTo("/greetings/me"))
        .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Bearer brice-access-token")));
  }

  /**
   * {@code oauth2-registration-id: keycloak-admin}: the client runs a {@code client_credentials}
   * flow and authorizes the request with the token it gets, not with the user's one. The static
   * {@code Accept} header of the client configuration is there too.
   */
  @Test
  @WithJwt(file = "brice.json", bearerString = "brice-access-token")
  void givenUserIsGrantedWithNice_whenGetUsers_thenCalledWithClientCredentialsToken()
      throws Exception {
    api.perform(get("/users")).andExpect(status().isOk())
        .andExpect(jsonPath("$[0].username").value("brice"));

    wireMock.verify(getRequestedFor(urlPathEqualTo("/auth/admin/realms/spring-addons/users"))
        .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Bearer m2m-access-token")));
  }

  @Test
  @WithJwt("igor.json")
  void givenUserIsNotGrantedWithNice_whenGetUsers_thenForbidden() throws Exception {
    api.perform(get("/users")).andExpect(status().isForbidden());
  }
}
