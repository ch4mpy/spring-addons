/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
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
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsWebfluxResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;
import com.c4_soft.springaddons.security.oidc.OAuthentication;

import reactor.core.publisher.Mono;

/**
 * <h2>Unit-test a secured controller</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

@WebFluxTest(GreetingController.class) // Use WebFluxTest or WebMvcTest
@AutoConfigureAddonsWebfluxResourceServerSecurity // If your web-security depends on it, setup
                                                  // spring-addons security
@Import({SecurityConfig.class}) // Import your web-security configuration
class GreetingControllerAnnotatedTest {

  // Mock controller injected dependencies
  @MockitoBean
  private MessageService messageService;

  @Autowired
  WebTestClientSupport api;

  @Autowired
  WithJwt.AuthenticationFactory authFactory;

  @BeforeEach
  public void setUp() {
    when(messageService.greet(any())).thenAnswer(invocation -> {
      final JwtAuthenticationToken auth = invocation.getArgument(0, JwtAuthenticationToken.class);
      return Mono.just(String.format("Hello %s! You are granted with %s.", auth.getName(),
          auth.getAuthorities()));
    });
    when(messageService.getSecret()).thenReturn(Mono.just("Secret message"));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
    api.get("https://localhost/greet").expectStatus().isUnauthorized();
  }

  @ParameterizedTest
  @MethodSource("auth0users")
  void givenUserIsAuthenticated_whenGetGreet_thenOk(
      @ParameterizedAuthentication Authentication auth) throws Exception {
    api.get("https://localhost/greet").expectBody(String.class).isEqualTo(
        "Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities()));
  }

  @Test
  @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class,
      name = "Tonton Pirate", authorities = "ROLE_AUTHORIZED_PERSONNEL")
  void givenUserIsMockedAsCh4mpy_whenGetGreet_thenOk() throws Exception {
    api.get("https://localhost/greet").expectBody(String.class)
        .isEqualTo("Hello Tonton Pirate! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
  }

  @Test
  @WithJwt("ch4mp.json")
  void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
    api.get("https://localhost/greet").expectBody(String.class).isEqualTo(
        "Hello ch4mp! You are granted with [USER_ROLES_EDITOR, ROLE_AUTHORIZED_PERSONNEL].");
  }

  @Test
  @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class)
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden()
      throws Exception {
    api.get("https://localhost/secured-route").expectStatus().isForbidden();
  }

  @Test
  @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class,
      authorities = "ROLE_AUTHORIZED_PERSONNEL")
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
    api.get("https://localhost/secured-route").expectStatus().isOk();
  }

  @Test
  @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class)
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden()
      throws Exception {
    api.get("https://localhost/secured-method").expectStatus().isForbidden();
  }

  @Test
  @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class,
      authorities = "ROLE_AUTHORIZED_PERSONNEL")
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
    api.get("https://localhost/secured-method").expectStatus().isOk();
  }

  /**
   * &#64;MethodSource for &#64;ParameterizedTest
   *
   * @return a stream of {@link OAuthentication OAuthentication&lt;OpenidClaimSet&gt;} as defined by
   *         the Authentication converter in the security configuration
   */
  Stream<AbstractAuthenticationToken> auth0users() {
    return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
  }
}
