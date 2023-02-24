package com.c4soft.springaddons.tutorials;

import java.util.Optional;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;

@RestController
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping("/greet")
	public String getGreeting(OAuthentication<OpenidClaimSet> auth) {
		return "Hi %s! You are granted with: %s."
				.formatted(Optional.ofNullable(auth.getAttributes().getPreferredUsername()).orElse(auth.getName()), auth.getAuthorities());
	}

	@GetMapping("/nice")
	@PreAuthorize("hasAuthority('NICE')")
	public String getNiceGreeting(OAuthentication<OpenidClaimSet> auth) {
		return "Dear %s! You are granted with: %s."
				.formatted(Optional.ofNullable(auth.getAttributes().getPreferredUsername()).orElse(auth.getName()), auth.getAuthorities());
	}
}
