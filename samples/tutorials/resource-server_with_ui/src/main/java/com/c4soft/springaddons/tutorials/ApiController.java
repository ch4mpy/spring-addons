package com.c4soft.springaddons.tutorials;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@PreAuthorize("isAuthenticated()")
public class ApiController {
	@GetMapping("/greet")
	public String getGreeting(JwtAuthenticationToken auth) {
		return "Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities());
	}
}
