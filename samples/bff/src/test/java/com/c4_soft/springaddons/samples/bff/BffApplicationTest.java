package com.c4_soft.springaddons.samples.bff;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Client;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.wiremock.spring.ConfigureWireMock;
import org.wiremock.spring.EnableWireMock;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOidcLogin;

/**
 * <p>
 * Full application context. An OAuth2 client fetches the OpenID configuration of each provider when
 * the {@code ClientRegistrationRepository} is created: WireMock stubs Keycloak's
 * {@code .well-known/openid-configuration} (and, on the same port, the resource server) from the
 * mappings in {@code src/test/resources/wiremock/keycloak}.
 * </p>
 * <p>
 * The session is never created by an actual login: {@code @WithOidcLogin} puts an
 * {@code OAuth2AuthenticationToken} with an {@code OidcUser} principal in the test security context.
 * </p>
 */
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@EnableWireMock(@ConfigureWireMock(name = "keycloak", port = 8089,
    filesUnderClasspath = "wiremock/keycloak"))
class BffApplicationTest {

  @Autowired
  MockMvc mockMvc;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetMe_thenAnonymousUserInfo() throws Exception {
    mockMvc.perform(get("/me")).andExpect(status().isOk())
        .andExpect(jsonPath("$.username").doesNotExist())
        .andExpect(jsonPath("$.roles").isEmpty())
        // the CSRF cookie is readable by JavaScript, so that the frontend can set the X-XSRF-TOKEN header
        .andExpect(cookie().httpOnly("XSRF-TOKEN", false));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetLoginOptions_thenOneOptionPerAuthorizationCodeRegistration()
      throws Exception {
    mockMvc.perform(get("/login-options")).andExpect(status().isOk())
        .andExpect(jsonPath("$[0].label").value("Keycloak"))
        .andExpect(jsonPath("$[0].loginUri").value("/oauth2/authorization/spring-addons-user"));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetProtectedRoute_thenUnauthorized() throws Exception {
    // oauth2-redirections.authentication-entry-point: UNAUTHORIZED (Spring default is a 302 to login)
    mockMvc.perform(get("/bff/api/greetings/me")).andExpect(status().isUnauthorized());
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenInitiateLogin_thenOkWithLocationToAuthorizationServer()
      throws Exception {
    mockMvc.perform(get("/oauth2/authorization/spring-addons-user"))
        // oauth2-redirections.pre-authorization-code: OK (Spring default is a 302)
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.LOCATION, startsWith(
            "http://localhost:8089/auth/realms/spring-addons/protocol/openid-connect/auth?")))
        // pkce-forced: true
        .andExpect(header().string(HttpHeaders.LOCATION, containsString("code_challenge_method=S256")))
        .andExpect(header().string(HttpHeaders.LOCATION,
            // client-uri is applied to the callback URI too
            containsString("redirect_uri=http://localhost:8080/login/oauth2/code/spring-addons-user")));
  }

  @Test
  @WithOidcLogin(authorities = "NICE", authorizedClientRegistrationId = "spring-addons-user",
      claims = @OpenIdClaims(preferredUsername = "brice", email = "brice@c4-soft.com"))
  void givenUserIsLoggedIn_whenGetMe_thenUserInfo() throws Exception {
    mockMvc.perform(get("/me")).andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("brice"))
        .andExpect(jsonPath("$.email").value("brice@c4-soft.com"))
        .andExpect(jsonPath("$.roles[0]").value("NICE"));
  }

  @Test
  @WithOidcLogin(authorizedClientRegistrationId = "spring-addons-user")
  void givenUserIsLoggedIn_whenLogout_thenAcceptedWithLocationToEndSessionEndpoint()
      throws Exception {
    mockMvc.perform(post("/logout").with(csrf()))
        // oauth2-redirections.rp-initiated-logout: ACCEPTED (Spring default is a 302)
        .andExpect(status().isAccepted())
        .andExpect(header().string(HttpHeaders.LOCATION, startsWith(
            "http://localhost:8089/auth/realms/spring-addons/protocol/openid-connect/logout?")))
        .andExpect(header().string(HttpHeaders.LOCATION, containsString("id_token_hint=")))
        .andExpect(header().string(HttpHeaders.LOCATION,
            containsString("post_logout_redirect_uri=http://localhost:8080/")));
  }

  @Test
  @WithOidcLogin(authorizedClientRegistrationId = "spring-addons-user")
  void givenUserIsLoggedInWithAuthorizedClient_whenGetProtectedRoute_thenRelayedWithBearer()
      throws Exception {
    final var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
        "access-token-from-session", Instant.now(), Instant.now().plusSeconds(60));
    // the WireMock stub for GET /greetings/me requires "Authorization: Bearer access-token-from-session"
    mockMvc.perform(get("/bff/api/greetings/me")
        .with(oauth2Client("spring-addons-user").accessToken(accessToken)))
        .andExpect(status().isOk()).andExpect(jsonPath("$.username").value("brice"));
  }
}
