package com.c4_soft.springaddons.samples.clientandresourceserver;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
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
import com.c4_soft.springaddons.security.oauth2.test.AuthenticationFactoriesTestConf;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOidcLogin;

/**
 * <p>
 * The point of this module: the same unauthorized request gets a different answer depending on which
 * filter chain processes it. {@code /ui/**} is in the client chain security matchers, so it is
 * redirected to login; {@code /api/**} is not, so it falls through to the resource server chain and
 * gets a 401.
 * </p>
 * <p>
 * The two chains also expect two different kinds of {@code Authentication}, which the test
 * annotations mirror: {@code @WithOidcLogin} (an {@code OAuth2AuthenticationToken}, as
 * {@code oauth2Login} builds) for the UI, {@code @WithJwt} (a {@code JwtAuthenticationToken}, built
 * from a claim-set by the application's converter) for the API.
 * </p>
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ImportAutoConfiguration(AuthenticationFactoriesTestConf.class)
@EnableWireMock(@ConfigureWireMock(name = "keycloak", port = 8089,
    filesUnderClasspath = "wiremock/keycloak"))
class TwoFilterChainsTest {

  @Autowired
  MockMvc mockMvc;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetUiPage_thenRedirectedToLogin() throws Exception {
    mockMvc.perform(get("/ui/greeting")).andExpect(status().isFound())
        .andExpect(header().string(HttpHeaders.LOCATION, startsWith("http://localhost:8084/login")));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetApiEndpoint_thenUnauthorized() throws Exception {
    // same application, same anonymous request, other chain: no redirection to login
    mockMvc.perform(get("/api/greetings/me")).andExpect(status().isUnauthorized())
        .andExpect(header().exists(HttpHeaders.WWW_AUTHENTICATE));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetIndex_thenOk() throws Exception {
    // "/" is in the client chain matchers and in its permit-all
    mockMvc.perform(get("/")).andExpect(status().isOk()).andExpect(view().name("index"))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("not authenticated")));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetPublicApiEndpoint_thenOk() throws Exception {
    // resource server permit-all
    mockMvc.perform(get("/api/greetings/public")).andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Hello, whoever you are."));
  }

  @Test
  // nameAttributeKey mirrors spring.security.oauth2.client.provider.keycloak.user-name-attribute:
  // without it, Authentication#getName() would be the "sub" claim
  @WithOidcLogin(authorities = "NICE", authorizedClientRegistrationId = "spring-addons-user",
      nameAttributeKey = "preferred_username",
      claims = @OpenIdClaims(preferredUsername = "brice"))
  void givenUserIsLoggedIn_whenGetIndex_thenGreetedByName() throws Exception {
    mockMvc.perform(get("/")).andExpect(status().isOk())
        .andExpect(content().string(org.hamcrest.Matchers.containsString("brice")));
  }

  @Test
  @WithJwt("brice.json")
  void givenRequestCarriesAnAccessToken_whenGetApiEndpoint_thenOk() throws Exception {
    mockMvc.perform(get("/api/greetings/me")).andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("brice"))
        .andExpect(jsonPath("$.message").value("Hi brice, this comes from the REST API."));
  }

  @Test
  @WithJwt("igor.json")
  void givenApiRequestIsAuthenticated_whenGetUiPage_thenStillRedirectedToLogin() throws Exception {
    // a JwtAuthenticationToken is not what the client chain accepts: the UI is secured with a session
    mockMvc.perform(get("/ui/greeting")).andExpect(status().isFound());
  }
}
