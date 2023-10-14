package com.c4_soft.dzone_oauth2_spring.official_greeting_api;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.constraints.NotEmpty;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class GreetingController {
	private final GreetingService greetingService;
	
	@GetMapping(path = "/greeting", produces = MediaType.APPLICATION_JSON_VALUE)
	@PreAuthorize("isAuthenticated()")
	public GreetingDto getGreeting() {
		return new GreetingDto(greetingService.getGreeting());
	}

	static record GreetingDto(@NotEmpty String message) {
	}
}
