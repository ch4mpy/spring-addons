/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.TestSecurityContextHolder;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsSecurity;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Import(MessageServiceTests.TestConfig.class)
@AutoConfigureAddonsSecurity
class MessageServiceTests {

    @Autowired
    private MessageService messageService;

    @Test()
    void greetWitoutAuthentication() {
        assertThrows(Exception.class, () -> messageService.getSecret());
    }

    /*--------------*/
    /* @WithMockJwt */
    /*--------------*/
    @Test
    @WithMockJwtAuth(authorities = "ROLE_AUTHORIZED_PERSONNEL", claims = @OpenIdClaims(preferredUsername = "ch4mpy"))
    void greetWithMockJwtAuth() {
        final JwtAuthenticationToken auth = (JwtAuthenticationToken) SecurityContextHolder.getContext()
                .getAuthentication();

        assertThat(messageService.greet(auth))
                .isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
    }

    @Test()
    @WithMockJwtAuth()
    void secretWithoutAuthorizedPersonnelGrant() {
        assertThrows(Exception.class, () -> messageService.getSecret());
    }

    @Test
    @WithMockJwtAuth("ROLE_AUTHORIZED_PERSONNEL")
    void secretWithAuthorizedPersonnelRole() {
        assertThat(messageService.getSecret()).isEqualTo("Secret message");
    }

    /*-------------------------*/
    /* @WithMockAuthentication */
    /*-------------------------*/
    @Test
    @WithMockAuthentication(authType = JwtAuthenticationToken.class, principalType = Jwt.class, name = "ch4mpy", authorities = "ROLE_AUTHORIZED_PERSONNEL")
    void greetWithMockAuthentication() {
        final var token = mock(Jwt.class);
        when(token.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME)).thenReturn("ch4mpy");
        final var auth = (JwtAuthenticationToken) TestSecurityContextHolder.getContext().getAuthentication();
        when(auth.getToken()).thenReturn(token);

        assertThat(messageService.greet(auth))
                .isEqualTo("Hello ch4mpy! You are granted with [ROLE_AUTHORIZED_PERSONNEL].");
    }

    @TestConfiguration(proxyBeanMethods = false)
    @EnableMethodSecurity
    @Import({ MessageService.class })
    static class TestConfig {
    }
}
