package com.c4_soft.springaddons.samples.resourceserver.greetings;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.samples.resourceserver.SecurityConfig;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.MockMvcSupport;

/**
 * <p>
 * A {@code @WebMvcTest} slice with the security configuration of the application: the
 * auto-configured resource server filter chain (with the {@code permit-all} and CORS properties),
 * plus the beans from {@link SecurityConfig}. Access tokens are never decoded: the
 * {@code Authentication} is put in the test security context by annotations.
 * </p>
 * <p>
 * {@code @WithJwt} loads a claim-set from the test classpath and runs it through the
 * <b>application's</b> authentication converter bean: the {@code Authentication} type, the username
 * and the authorities are exactly what they would be at runtime for a token with these claims.
 * </p>
 */
@WebMvcTest(GreetingsController.class)
@AutoConfigureAddonsWebmvcResourceServerSecurity
@Import({SecurityConfig.class, GreetingsService.class})
class GreetingsControllerTest {

  @Autowired
  MockMvcSupport api;

  @Autowired
  WithJwt.AuthenticationFactory authFactory;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetPublic_thenOk() throws Exception {
    api.get("/greetings/public").andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Hello, whoever you are."));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetMe_thenUnauthorized() throws Exception {
    api.get("/greetings/me").andExpect(status().isUnauthorized());
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenGetMe_thenGreetedWithKeycloakClaims() throws Exception {
    api.get("/greetings/me").andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Hi Brice! You are granted with [NICE, default-roles-spring-addons, offline_access, uma_authorization]."))
        // username-claim is preferred_username for the Keycloak issuer (not the sub UUID)
        .andExpect(jsonPath("$.username").value("brice"))
        .andExpect(jsonPath("$.issuer").value("http://localhost:7080/auth/realms/spring-addons"))
        // authorities were mapped from $.realm_access.roles by the auto-configured converter
        .andExpect(jsonPath("$.authorities").value(hasItem("NICE")));
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenGetNice_thenOk() throws Exception {
    api.get("/greetings/nice").andExpect(status().isOk())
        .andExpect(jsonPath("$.message").value("Dear brice, glad to see you!"));
  }

  @Test
  @WithJwt("igor.json")
  void givenUserIsIgor_whenGetNice_thenForbidden() throws Exception {
    api.get("/greetings/nice").andExpect(status().isForbidden());
  }

  /**
   * JUnit 5 parameterized test: one execution per claim-set file, the {@code Authentication} built
   * by the application's converter being injected as a test parameter.
   */
  @ParameterizedTest
  @MethodSource("identities")
  void givenUserIsAuthenticated_whenGetMe_thenGreetedWithItsName(
      @ParameterizedAuthentication Authentication auth) throws Exception {
    api.get("/greetings/me").andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value(auth.getName()))
        .andExpect(jsonPath("$.authorities").value(hasItem("default-roles-spring-addons")));
  }

  Stream<AbstractAuthenticationToken> identities() {
    return authFactory.authenticationsFrom("brice.json", "igor.json");
  }
}
