package com.c4_soft.dzone_oauth2_spring.c4_greeting_api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockAuthentication;

@ExtendWith(SpringExtension.class)
@Import(GreetingService.class)
@EnableMethodSecurity
class GreetingServiceTest {
	@Autowired
	GreetingService greetingService;

	@Test
	void givenSecurityContextIsEmpty_whenGetGreeting_thenThrows() {
		assertThrows(AuthenticationCredentialsNotFoundException.class, () -> greetingService.getGreeting());
	}

	@Test
	@WithAnonymousUser
	void givenSecurityContextIsAnonymous_whenGetGreeting_thenThrows() {
		assertThrows(AccessDeniedException.class, () -> greetingService.getGreeting());
	}

	@Test
	@WithMockAuthentication(name = "ch4mp", authorities = {"NICE", "AUTHOR"})
	void givenUserHasMockedAuthentication_whenGetGreeting_thenOk() {
		assertEquals("Hello ch4mp! You are granted with [NICE, AUTHOR].", greetingService.getGreeting());
	}

}
