package com.c4soft.springaddons.tutorials;

import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;

@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping()
	public String getGreeting(BearerTokenAuthentication auth) {
		final var claims = new OpenidClaimSet(auth.getTokenAttributes());
		return String
				.format(
						"Hi %s! You are granted with: %s.",
						claims.getPreferredUsername(),
						auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")));
	}
}
