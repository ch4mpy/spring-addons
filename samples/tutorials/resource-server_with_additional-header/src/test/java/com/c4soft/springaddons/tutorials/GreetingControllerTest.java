package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt.AutoConfigureAddonsWebSecurity;
import com.c4soft.springaddons.tutorials.ServletResourceServerWithAdditionalHeader.SecurityConfig;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import(SecurityConfig.class)
class GreetingControllerTest {

    @Autowired
    MockMvcSupport api;

    @Test
    @WithMyAuth(authorities = { "AUTHOR" }, idClaims = @OpenIdClaims(email = "ch4mp@c4-soft.com"))
    void givenUserIsAuthenticated_whenGreet_thenOk() throws Exception {
        api.get("/greet").andExpect(status().isOk())
                .andExpect(content().string("Hi ch4mp@c4-soft.com! You are granted with: [AUTHOR]."));
    }

    @Test
    void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
        api.get("/greet").andExpect(status().isUnauthorized());
    }

}
