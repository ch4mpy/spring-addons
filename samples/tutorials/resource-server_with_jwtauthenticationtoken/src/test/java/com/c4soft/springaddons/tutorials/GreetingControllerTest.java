package com.c4soft.springaddons.tutorials;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import jakarta.servlet.http.HttpServletRequest;

@WebMvcTest(controllers = GreetingController.class, properties = "server.ssl.enabled=false")
@Import({ SecurityConfig.class })
class GreetingControllerTest {

	@MockBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Autowired
	MockMvc mockMvc;

	@Test
	void whenGrantedNiceRoleThenOk() throws Exception {
		mockMvc.perform(get("/greet").with(jwt().jwt(jwt -> {
			jwt.claim("preferred_username", "Tonton Pirate");
		}).authorities(List.of(new SimpleGrantedAuthority("NICE"), new SimpleGrantedAuthority("AUTHOR"))))).andExpect(status().isOk())
				.andExpect(content().string("Hi Tonton Pirate! You are granted with: [NICE, AUTHOR]."));
	}

	@Test
	void whenNotGrantedNiceRoleThenForbidden() throws Exception {
		mockMvc.perform(get("/greet").with(jwt().jwt(jwt -> {
			jwt.claim("preferred_username", "Tonton Pirate");
		}).authorities(List.of(new SimpleGrantedAuthority("AUTHOR"))))).andExpect(status().isForbidden());
	}

	@Test
	void whenAnonymousThenUnauthorized() throws Exception {
		mockMvc.perform(get("/greet")).andExpect(status().isUnauthorized());
	}
}
