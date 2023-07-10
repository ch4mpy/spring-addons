package com.c4soft.springaddons.tutorials;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/greet", produces = MediaType.APPLICATION_JSON_VALUE)
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE')")
	public MessageDto getGreeting(Authentication auth) {
		return new MessageDto("Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities()));
	}

	public static record MessageDto(String body) {
	}
}
