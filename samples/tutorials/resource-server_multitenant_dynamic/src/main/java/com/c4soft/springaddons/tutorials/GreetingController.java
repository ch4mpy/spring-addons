package com.c4soft.springaddons.tutorials;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping("/greet")
	public MessageDto getGreeting(JwtAuthenticationToken auth) {
		return new MessageDto(
				"Hi %s! You are granted with: %s and your email is %s."
						.formatted(auth.getName(), auth.getAuthorities(), auth.getTokenAttributes().get(StandardClaimNames.EMAIL)));
	}

	@GetMapping("/nice")
	@PreAuthorize("hasAuthority('NICE')")
	public MessageDto getNiceGreeting(JwtAuthenticationToken auth) {
		return new MessageDto("Dear %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities()));
	}

	static record MessageDto(String body) {
	}
}
