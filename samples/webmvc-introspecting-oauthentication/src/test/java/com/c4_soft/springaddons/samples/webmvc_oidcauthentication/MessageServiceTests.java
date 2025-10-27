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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithOpaqueToken;
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

  // mock dependencies
  @MockitoBean
  SecretRepo secretRepo;

  @BeforeEach
  public void setUp() {
    when(secretRepo.findSecretByUsername(anyString())).thenReturn("incredible");
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetSecret_thenThrows() {
    // call tested components methods directly (do not use MockMvc nor WebTestClient)
    assertThrows(Exception.class, () -> messageService.getSecret());
  }

  @Test
  @WithAnonymousUser
  void givenRequestIsAnonymous_whenGetGreet_thenThrows() {
    assertThrows(Exception.class, () -> messageService.greet(null));
  }

  @Test
  @WithOpaqueToken("tonton-pirate.json")
  void givenUserIsNotGrantedWithAuthorizedPersonnel_whenGetSecret_thenThrows() {
    assertThrows(Exception.class, () -> messageService.getSecret());
  }

  @Test
  @WithOpaqueToken("ch4mp.json")
  void givenUserIsGrantedWithAuthorizedPersonnel_whenGetSecret_thenReturnsSecret() {
    assertThat(messageService.getSecret()).isEqualTo("incredible");
  }

  @SuppressWarnings("unchecked")
  @Test
  @WithOpaqueToken("ch4mp.json")
  void givenUserIsAuthenticated_whenGetGreet_thenReturnsGreeting() {
    final var auth =
        (OAuthentication<OpenidToken>) SecurityContextHolder.getContext().getAuthentication();

    assertThat(messageService.greet(auth))
        .isEqualTo("Hello ch4mp! You are granted with [NICE, AUTHOR, ROLE_AUTHORIZED_PERSONNEL].");
  }
}
