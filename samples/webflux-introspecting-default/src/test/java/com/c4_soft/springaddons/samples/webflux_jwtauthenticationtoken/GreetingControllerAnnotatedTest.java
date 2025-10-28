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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsWebfluxResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;
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

  @BeforeEach
  public void setUp() {
    when(messageService.greet(any())).thenAnswer(invocation -> {
      final BearerTokenAuthentication auth =
          invocation.getArgument(0, BearerTokenAuthentication.class);
      return Mono.just(String.format("Hello %s! You are granted with %s.", auth.getName(),
          auth.getAuthorities()));
    });
    when(messageService.getSecret()).thenReturn(Mono.just("Secret message"));
  }

  @Test
  void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
    api.get("https://localhost/greet").expectStatus().isUnauthorized();
  }

  @Test
  @WithMockAuthentication(authType = BearerTokenAuthentication.class,
      principalType = OAuth2AccessToken.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
  void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
    api.get("https://localhost/greet").expectBody(String.class)
        .isEqualTo("Hello user! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
  }

  @Test
  @WithMockAuthentication(authType = BearerTokenAuthentication.class,
      principalType = OAuth2AccessToken.class, name = "Ch4mpy",
      authorities = "ROLE_AUTHORIZED_PERSONNEL")
  void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
    api.get("https://localhost/greet").expectBody(String.class)
        .isEqualTo("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
  }

  @Test
  @WithMockAuthentication(authType = BearerTokenAuthentication.class,
      principalType = OAuth2AccessToken.class)
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden()
      throws Exception {
    api.get("https://localhost/secured-route").expectStatus().isForbidden();
  }

  @Test
  @WithMockAuthentication(authType = BearerTokenAuthentication.class,
      principalType = OAuth2AccessToken.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
    api.get("https://localhost/secured-route").expectStatus().isOk();
  }

  @Test
  @WithMockAuthentication(authType = BearerTokenAuthentication.class,
      principalType = OAuth2AccessToken.class)
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden()
      throws Exception {
    api.get("https://localhost/secured-method").expectStatus().isForbidden();
  }

  @Test
  @WithMockAuthentication(authType = BearerTokenAuthentication.class,
      principalType = OAuth2AccessToken.class, authorities = "ROLE_AUTHORIZED_PERSONNEL")
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
    api.get("https://localhost/secured-method").expectStatus().isOk();
  }
}
