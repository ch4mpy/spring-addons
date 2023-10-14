package com.c4_soft.dzone_oauth2_spring.c4_greeting_api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class GreetingService {

	@PreAuthorize("isAuthenticated()")
	public String getGreeting() {
		final var auth = SecurityContextHolder.getContext().getAuthentication();
		return "Hello %s! You are granted with %s.".formatted(auth.getName(), auth.getAuthorities());
	}
}
