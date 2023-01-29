package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AutoConfigureAddonsWebSecurity;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;
import com.c4soft.springaddons.tutorials.ResourceServerWithOAuthenticationApplication.SecurityConfig;

@WebMvcTest(controllers = GreetingController.class)
@AutoConfigureAddonsWebSecurity
@Import(SecurityConfig.class)
class GreetingControllerTest {

    @Autowired
    MockMvcSupport api;

    @Test
    @OpenId(authorities = { "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void whenAuthenticatedThenCanGreet() throws Exception {
        api.get("/greet").andExpect(status().isOk())
                .andExpect(content().string("Hi Tonton Pirate! You are granted with: [AUTHOR]."));
    }

    @Test
    void whenAnonymousThenUnauthorizedToGreet() throws Exception {
        api.get("/greet").andExpect(status().isUnauthorized());
    }

    @Test
    @OpenId(authorities = { "NICE", "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void whenGrantedWithNiceRoleThenCanGetNiceGreeting() throws Exception {
        api.get("/nice").andExpect(status().isOk())
                .andExpect(content().string("Dear Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
    }

    @Test
    @OpenId(authorities = { "AUTHOR" }, claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
    void whenNotGrantedWithNiceRoleThenForbiddenToGetNiceGreeting() throws Exception {
        api.get("/nice").andExpect(status().isForbidden());
    }

    @Test
    void whenAnonymousThenUnauthorizedToGetNiceGreeting() throws Exception {
        api.get("/nice").andExpect(status().isUnauthorized());
    }

}
