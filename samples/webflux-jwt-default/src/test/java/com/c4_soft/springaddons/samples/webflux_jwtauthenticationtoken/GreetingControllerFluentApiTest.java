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

import static com.c4_soft.springaddons.security.oauth2.test.webflux.MockAuthenticationWebTestClientConfigurer.mockAuthentication;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsWebfluxResourceServerSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webflux.MockAuthenticationWebTestClientConfigurer;
import com.c4_soft.springaddons.security.oauth2.test.webflux.WebTestClientSupport;

import reactor.core.publisher.Mono;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@WebFluxTest(GreetingController.class)
@AutoConfigureAddonsWebfluxResourceServerSecurity
@Import({SecurityConfig.class})
public class GreetingControllerFluentApiTest {
  private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
      "anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

  @MockitoBean
  private MessageService messageService;

  @Autowired
  WebTestClientSupport api;

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
  void givenRequestIsUnauthorized_whenGetGreet_thenUnauthorized() throws Exception {
    api.mutateWith(SecurityMockServerConfigurers.mockAuthentication(ANONYMOUS_AUTHENTICATION))
        .get("https://localhost/greet").expectStatus().isUnauthorized();
  }

  @Test
  void givenUserIsCh4mpy_whenGetGreet_thenOk() throws Exception {
    api.mutateWith(ch4mpy()).get("https://localhost/greet").expectBody(String.class)
        .isEqualTo("Hello Ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
  }

  @Test
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden()
      throws Exception {
    api.mutateWith(mockAuthentication(JwtAuthenticationToken.class))
        .get("https://localhost/secured-route").expectStatus().isForbidden();
  }

  @Test
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden()
      throws Exception {
    api.mutateWith(mockAuthentication(JwtAuthenticationToken.class))
        .get("https://localhost/secured-method").expectStatus().isForbidden();
  }

  @Test
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
    api.mutateWith(ch4mpy()).get("https://localhost/secured-route").expectStatus().isOk();
  }

  @Test
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
    api.mutateWith(ch4mpy()).get("https://localhost/secured-method").expectStatus().isOk();
  }

  private MockAuthenticationWebTestClientConfigurer<JwtAuthenticationToken> ch4mpy() {
    return mockAuthentication(JwtAuthenticationToken.class).name("Ch4mpy")
        .authorities("ROLE_AUTHORIZED_PERSONNEL");
  }
}
