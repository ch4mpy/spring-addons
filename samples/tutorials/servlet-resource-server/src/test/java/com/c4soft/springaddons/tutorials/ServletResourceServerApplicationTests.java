package com.c4soft.springaddons.tutorials;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import jakarta.servlet.http.HttpServletRequest;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK, properties = { "server.ssl.enabled=false" })
@AutoConfigureMockMvc
class ServletResourceServerApplicationTests {

	@MockitoBean
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Autowired
	MockMvc api;

	@Test
	void givenRequestIsNotAuthorized_whenGreet_thenUnauthorized() throws Exception {
		api.perform(get("/greet").with(SecurityMockMvcRequestPostProcessors.anonymous())).andExpect(status().isUnauthorized());
	}

	@Test
	void givenUserAuthenticated_whenGreet_thenOk() throws Exception {
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
	void givenUserIsNotNicewhenGetRestricted_thenForbidden() throws Exception {
		// @formatter:off
		api.perform(get("/restricted").with(SecurityMockMvcRequestPostProcessors.jwt().authorities(new SimpleGrantedAuthority("AUTHOR"))))
				.andExpect(status().isForbidden());
		// @formatter:on
	}

}
