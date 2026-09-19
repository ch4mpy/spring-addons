package com.c4_soft.springaddons.samples.resourceserver.greetings;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithAnonymousUser;
import com.c4_soft.springaddons.samples.resourceserver.ResourceServerReactiveApplication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.AuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsWebfluxResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;

/**
 * The reactive twin of the servlet {@code GreetingsControllerTest}: {@code @WebFluxTest},
 * {@code @AutoConfigureAddonsWebfluxResourceServerSecurity} and {@code WebTestClientSupport}. The
 * annotations populating the test security context are the same.
 */
@WebFluxTest(GreetingsController.class)
@AutoConfigureAddonsWebfluxResourceServerSecurity
@Import({ResourceServerReactiveApplication.class, GreetingsService.class})
class GreetingsControllerTest {

  @Autowired
  WebTestClientSupport api;

  @Autowired
  WithJwt.AuthenticationFactory authFactory;

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetPublic_thenOk() {
    api.get("/greetings/public").expectStatus().isOk().expectBody().jsonPath("$.message")
        .isEqualTo("Hello, whoever you are.");
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetMe_thenUnauthorized() {
    api.get("/greetings/me").expectStatus().isUnauthorized();
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenGetMe_thenGreetedWithKeycloakClaims() {
    api.get("/greetings/me").expectStatus().isOk().expectBody()
        .jsonPath("$.message").isEqualTo("Hi Brice! You are granted with [NICE, default-roles-spring-addons, offline_access, uma_authorization].")
        // username-claim is preferred_username for the Keycloak issuer (not the sub UUID)
        .jsonPath("$.username").isEqualTo("brice")
        .jsonPath("$.issuer").isEqualTo("http://localhost:7080/auth/realms/spring-addons")
        // authorities were mapped from $.realm_access.roles by the auto-configured converter
        .jsonPath("$.authorities[?(@ == 'NICE')]").exists();
  }

  @Test
  @WithJwt("brice.json")
  void givenUserIsBrice_whenGetNice_thenOk() {
    api.get("/greetings/nice").expectStatus().isOk().expectBody().jsonPath("$.message")
        .isEqualTo("Dear brice, glad to see you!");
  }

  @Test
  @WithJwt("igor.json")
  void givenUserIsIgor_whenGetNice_thenForbidden() {
    api.get("/greetings/nice").expectStatus().isForbidden();
  }

  /**
   * {@code @WithMockAuthentication} builds a Mockito mock of the requested {@code Authentication}
   * type, stubbing only its name, authorities and principal: enough for RBAC (no claim-set file
   * needed), but the endpoints of this sample read claims, so it is used only where access is
   * denied before any claim is read. Use {@code @WithJwt} when the tested code reads claims.
   */
  @ParameterizedTest
  @AuthenticationSource({
      @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class,
          name = "igor"),
      @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class,
          name = "grumpy", authorities = {"NOT_NICE", "GRUMPY"})})
  void givenUserIsNotGrantedWithNice_whenGetNice_thenForbidden(
      @ParameterizedAuthentication Authentication auth) {
    api.get("/greetings/nice").expectStatus().isForbidden();
  }

  /**
   * One execution per claim-set file, the {@code Authentication} built by the application's
   * converter being injected as a test parameter.
   */
  @ParameterizedTest
  @MethodSource("identities")
  void givenUserIsAuthenticated_whenGetMe_thenGreetedWithItsName(
      @ParameterizedAuthentication Authentication auth) {
    api.get("/greetings/me").expectStatus().isOk().expectBody().jsonPath("$.username")
        .isEqualTo(auth.getName());
  }

  Stream<AbstractAuthenticationToken> identities() {
    return authFactory.authenticationsFrom("brice.json", "igor.json");
  }
}
