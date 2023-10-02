package com.c4soft.springaddons.samples.bff.users.web;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import io.micrometer.observation.annotation.Observed;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotEmpty;

@RestController
@Tag(name = "Greetings")
@Observed(name = "GreetingsController")
public class GreetingsController {

	@GetMapping(path = "/greetings/public", produces = MediaType.APPLICATION_JSON_VALUE)
	@Tag(name = "getPublicGreeting")
	@PreAuthorize("isAuthenticated()")
	public GreetingDto getGreeting(JwtAuthenticationToken auth) {
		return new GreetingDto(
				"Hi %s! You are authenticated by %s and granted with: %s."
						.formatted(auth.getName(), auth.getTokenAttributes().get(JwtClaimNames.ISS), auth.getAuthorities()));
	}

	@GetMapping(path = "/greetings/nice", produces = MediaType.APPLICATION_JSON_VALUE)
	@Tag(name = "getNiceGreeting")
	@PreAuthorize("hasAuthority('NICE')")
	public GreetingDto getNiceGreeting(JwtAuthenticationToken auth) {
		return new GreetingDto(
				"Dear %s! You are authenticated by %s and granted with: %s."
						.formatted(auth.getName(), auth.getTokenAttributes().get(JwtClaimNames.ISS), auth.getAuthorities()));
	}

	/**
	 * @param  message the greeting body
	 * @author         Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	static record GreetingDto(@NotEmpty String message) {
	}
}
