package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenId;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.MockMvcSupport;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ImportAutoConfiguration({ AddonsWebmvcTestConf.class })
class ResourceServerWithOAuthenticationApplicationTests {
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
