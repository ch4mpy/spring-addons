package com.c4soft.springaddons.tutorials;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.test.web.servlet.MockMvc;

import jakarta.servlet.http.HttpServletRequest;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK, classes = {
        ResourceServerWithJwtAuthenticationTokenApplication.class, SecurityConfig.class })
@AutoConfigureMockMvc
class ResourceServerWithJwtAuthenticationTokenApplicationTests {

    @MockBean
    AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

    @Autowired
    MockMvc api;

    @Autowired
    ServerProperties serverProperties;

    @Test
    void givenRequestIsAnonymous_whenGreet_thenUnauthorized() throws Exception {
        api.perform(get("/greet").secure(isSslEnabled())).andExpect(status().isUnauthorized());
    }

    @Test
    void givenUserIsGrantedWithNice_whenGreet_thenOk() throws Exception {
        api.perform(
                get("/greet").secure(isSslEnabled()).with(
                        jwt().authorities(
                                List.of(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR")))
                                .jwt(jwt -> jwt.claim(StandardClaimNames.PREFERRED_USERNAME, "Tonton Pirate"))))
                .andExpect(status().isOk())
                .andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
    }

    private boolean isSslEnabled() {
        return serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled();
    }

}
