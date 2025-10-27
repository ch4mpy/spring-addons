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
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsWebfluxResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

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
  WithOpaqueToken.AuthenticationFactory authFactory;

  @BeforeEach
  public void setUp() {
    when(messageService.greet(any())).thenAnswer(invocation -> {
      @SuppressWarnings("unchecked")
      final OAuthentication<OpenidToken> auth = invocation.getArgument(0, OAuthentication.class);
      return Mono.just(String.format("Hello %s! You are granted with %s.",
          auth.getAttributes().getPreferredUsername(), auth.getAuthorities()));
    });
    when(messageService.getSecret()).thenReturn(Mono.just("Secret message"));
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
    api.get("https://localhost/greet").expectStatus().isUnauthorized();
  }

  @ParameterizedTest
  @MethodSource("identities")
  void givenUserIsCh4mpy_whenGetGreet_thenOk(@ParameterizedAuthentication Authentication auth)
      throws Exception {
    api.get("https://localhost/greet").expectBody(String.class).isEqualTo(
        "Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities()));
  }

  Stream<Authentication> identities() {
    return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
  }

  @Test
  @WithOpaqueToken("tonton-pirate.json")
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden()
      throws Exception {
    api.get("https://localhost/secured-route").expectStatus().isForbidden();
  }

  @Test
  @WithOpaqueToken("ch4mp.json")
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
    api.get("https://localhost/secured-route").expectStatus().isOk();
  }

  @Test
  @WithOpaqueToken("tonton-pirate.json")
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden()
      throws Exception {
    api.get("https://localhost/secured-method").expectStatus().isForbidden();
  }

  @Test
  @WithOpaqueToken("ch4mp.json")
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
    api.get("https://localhost/secured-method").expectStatus().isOk();
  }
}
