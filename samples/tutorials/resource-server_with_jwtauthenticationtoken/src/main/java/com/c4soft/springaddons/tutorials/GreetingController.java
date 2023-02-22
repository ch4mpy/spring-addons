package com.c4soft.springaddons.tutorials;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {

	@GetMapping("/greet")
	public String getGreeting(Authentication auth) {
		return "Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities());
	}
}
