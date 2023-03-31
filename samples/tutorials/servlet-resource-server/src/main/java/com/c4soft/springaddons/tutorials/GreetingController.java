package com.c4soft.springaddons.tutorials;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

	@GetMapping("/greet")
	public Message getGreeting(Authentication auth) {
		return new Message("Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities()));
	}

	@GetMapping("/restricted")
	@PreAuthorize("hasAuthority('NICE')")
	public Message getRestricted() {
		return new Message("You are so nice!");
	}

	static record Message(String body) {
	}
}