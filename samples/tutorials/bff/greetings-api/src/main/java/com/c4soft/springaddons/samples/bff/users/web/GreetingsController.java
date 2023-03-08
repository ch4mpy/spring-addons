package com.c4soft.springaddons.samples.bff.users.web;

import java.io.Serializable;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@RestController
@RequestMapping(path = "/greetings", produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "Greetings")
public class GreetingsController {
	@GetMapping()
	@Tag(name = "get")
	public GreetingDto getGreeting(OAuthentication<OpenidClaimSet> auth) {
		return new GreetingDto(
				"Hi %s! You are authenticated by %s and granted with: %s.".formatted(auth.getName(), auth.getAttributes().getIssuer(), auth.getAuthorities()));
	}

	@Data
	@AllArgsConstructor
	@Builder
	public static class GreetingDto implements Serializable {
		private static final long serialVersionUID = -5404506920234624316L;

		private String message;
	}
}
