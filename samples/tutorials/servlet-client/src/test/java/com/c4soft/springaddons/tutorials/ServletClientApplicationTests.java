package com.c4soft.springaddons.tutorials;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(ServletClientApplicationTests.TestSecurityConf.class)
class ServletClientApplicationTests {

	@Autowired
	MockMvc mockMvc;

	@Test
	void givenRequestIsNotAuthorized_whenGetIndex_thenIsOk() throws Exception {
		mockMvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	void givenUserIsAnonymous_whenGetIndex_thenIsOk() throws Exception {
		mockMvc.perform(get("/").with(SecurityMockMvcRequestPostProcessors.anonymous())).andExpect(status().isOk());
	}

	@Test
	void givenUserIsAuthenticated_whenGetIndex_thenIsOk() throws Exception {
		mockMvc.perform(get("/").with(SecurityMockMvcRequestPostProcessors.oauth2Login())).andExpect(status().isOk());
	}

	@Test
	void givenRequestIsNotAuthorized_whenGetLogin_thenIsOk() throws Exception {
		mockMvc.perform(get("/login")).andExpect(status().isOk());
	}

	@Test
	void givenUserIsAnonymous_whenGetLogin_thenIsOk() throws Exception {
		mockMvc.perform(get("/login").with(SecurityMockMvcRequestPostProcessors.anonymous())).andExpect(status().isOk());
	}

	@Test
	void givenUserIsAuthenticated_whenGetLogin_thenIsRedirected() throws Exception {
		mockMvc.perform(get("/login").with(SecurityMockMvcRequestPostProcessors.oauth2Login())).andExpect(status().is3xxRedirection());
	}

	@Test
	void givenRequestIsNotAuthorized_whenGetNice_thenIsRedirected() throws Exception {
		mockMvc.perform(get("/nice.html")).andExpect(status().is3xxRedirection());
	}

	@Test
	void givenUserIsAnonymous_whenGetNice_thenIsRedirected() throws Exception {
		mockMvc.perform(get("/nice.html").with(SecurityMockMvcRequestPostProcessors.anonymous())).andExpect(status().is3xxRedirection());
	}

	@Test
	void givenUserIsNice_whenGetNice_thenIsOk() throws Exception {
		mockMvc.perform(get("/nice.html").with(SecurityMockMvcRequestPostProcessors.oauth2Login().authorities(new SimpleGrantedAuthority("NICE"))))
				.andExpect(status().isOk());
	}

	@Test
	void givenUserIsNotNice_whenGetNice_thenIsForbidden() throws Exception {
		mockMvc.perform(get("/nice.html").with(SecurityMockMvcRequestPostProcessors.oauth2Login())).andExpect(status().isForbidden());
	}

	@TestConfiguration
	static class TestSecurityConf {
		@Bean
		InMemoryClientRegistrationRepository clientRegistrationRepository() {
			final var clientRegistrationRepository = mock(InMemoryClientRegistrationRepository.class);
			when(clientRegistrationRepository.iterator()).thenReturn(new ArrayList<ClientRegistration>().iterator());
			when(clientRegistrationRepository.spliterator()).thenReturn(new ArrayList<ClientRegistration>().spliterator());
			return clientRegistrationRepository;
		}
	}
}
