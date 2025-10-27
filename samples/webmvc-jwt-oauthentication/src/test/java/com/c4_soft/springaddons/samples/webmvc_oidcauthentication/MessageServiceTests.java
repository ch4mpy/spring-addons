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
package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcComponentTest;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

/**
 * <h2>Unit-test a secured service or repository which has injected dependencies</h2>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */

// Import security configuration and test component
@AddonsWebmvcComponentTest
@SpringBootTest(classes = {SecurityConfig.class, MessageService.class})
class MessageServiceTests {

  // auto-wire tested component
  @Autowired
  private MessageService messageService;

  @Autowired
  WithJwt.AuthenticationFactory authFactory;

  // mock dependencies
  @MockitoBean
  SecretRepo secretRepo;

  @BeforeEach
  public void setUp() {
    when(secretRepo.findSecretByUsername(anyString())).thenReturn("incredible");
  }

  @Test()
  void givenRequestIsAnonymous_whenGetSecret_thenThrows() {
    // call tested components methods directly (do not use MockMvc nor WebTestClient)
    assertThrows(Exception.class, () -> messageService.getSecret());
  }

  @Test()
  void givenRequestIsAnonymous_whenGetGreet_thenThrows() {
    assertThrows(Exception.class, () -> messageService.greet(null));
  }

  /*--------------*/
  /* @WithMockJwt */
  /*--------------*/
  @Test()
  @WithJwt("tonton-pirate.json")
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecret_thenThrows() {
    assertThrows(Exception.class, () -> messageService.getSecret());
  }

  @Test
  @WithJwt("ch4mp.json")
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecret_thenReturnsSecret() {
    assertThat(messageService.getSecret()).isEqualTo("incredible");
  }

  @SuppressWarnings("unchecked")
  @ParameterizedTest
  @MethodSource("identities")
  void givenUserIsAuthenticated_whenGetGreet_thenReturnsGreeting(
      @ParameterizedAuthentication Authentication auth) {
    final var oauth = (OAuthentication<OpenidToken>) auth;
    assertThat(messageService.greet(oauth)).isEqualTo(
        "Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities()));
  }

  Stream<AbstractAuthenticationToken> identities() {
    return authFactory.authenticationsFrom("ch4mp.json", "tonton-pirate.json");
  }
}
