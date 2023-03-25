package com.c4soft.springaddons.tutorials;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
@Import(ServletClientApplicationTests.TestSecurityConf.class)
class ServletClientApplicationTests {

	@Test
	void contextLoads() {
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
