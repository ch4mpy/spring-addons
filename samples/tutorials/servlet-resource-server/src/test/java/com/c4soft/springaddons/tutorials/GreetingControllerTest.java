package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.AuthenticationSource;
import com.c4_soft.springaddons.security.oauth2.test.annotations.parameterized.ParameterizedAuthentication;

import jakarta.servlet.http.HttpServletRequest;

@WebMvcTest(controllers = GreetingController.class, properties = { "server.ssl.enabled=false" })
@Import({ WebSecurityConfig.class })
class GreetingControllerTest {

    @MockBean
    AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

    @Autowired
    MockMvc api;

    @Test
    void givenRequestIsNotAuthorized_whenGetGreet_thenUnauthorized() throws Exception {
        api.perform(get("/greet")).andExpect(status().isUnauthorized());
    }

    @Test
    void givenUserAuthenticated_whenGetGreet_thenOk() throws Exception {
        // @formatter:off
		api.perform(get("/greet").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR"))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("Hi user! You are granted with: [NICE, AUTHOR]."));
		// @formatter:on
    }

    @Test
    void givenRequestIsNotAuthorized_whenGetRestricted_thenUnauthorized() throws Exception {
        api.perform(get("/restricted")).andExpect(status().isUnauthorized());
    }

    @Test
    void givenUserIsNice_whenGetRestricted_thenOk() throws Exception {
        // @formatter:off
		api.perform(get("/restricted").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR"))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
    }

    @Test
    @WithMockAuthentication("NICE")
    void givenMockAuthenticationWithNice_whenGetRestricted_thenOk() throws Exception {
        // @formatter:off
		api.perform(get("/restricted"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
    }

    @Test
    @WithJwt("ch4mp_auth0.json")
    void givenJwtWithNice_whenGetRestricted_thenOk() throws Exception {
        // @formatter:off
		api.perform(get("/restricted"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
    }

    @Test
    void givenUserIsNotNice_whenGetRestricted_thenForbidden() throws Exception {
        // @formatter:off
		api.perform(get("/restricted").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority("AUTHOR"))))
				.andExpect(status().isForbidden());
		// @formatter:on
    }

    @ParameterizedTest
    @ValueSource(strings = { "NICE", "VERY_NICE" })
    void givenUserIsGrantedWithAnyNiceAuthority_whenGetRestricted_thenOk(String authority) throws Exception {
        // @formatter:off
		api.perform(get("/restricted").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority(authority))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
    }

    @ParameterizedTest
    @AuthenticationSource({ @WithMockAuthentication("NICE"), @WithMockAuthentication("VERY_NICE") })
    void givenUserIsGrantedWithAnyJwtAuthentication_whenGetRestricted_thenOk(@ParameterizedAuthentication Authentication auth) throws Exception {
        // @formatter:off
		api.perform(get("/restricted"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.body").value("You are so nice!"));
		// @formatter:on
    }
}
