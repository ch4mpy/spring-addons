package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class GreetingController {
	private final MessageService messageService;

	@GetMapping("/greet")
	public ResponseEntity<String> greet(JwtAuthenticationToken auth) {
		return ResponseEntity.ok(messageService.greet(auth));
	}

	@GetMapping("/secured-route")
	public ResponseEntity<String> securedRoute() {
		return ResponseEntity.ok(messageService.getSecret());
	}

	@GetMapping("/secured-method")
	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	public ResponseEntity<String> securedMethod() {
		return ResponseEntity.ok(messageService.getSecret());
	}

	@GetMapping("/claims")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<Map<String, Object>> getClaims(JwtAuthenticationToken auth) {
		return ResponseEntity.ok(auth.getTokenAttributes());
	}
}
