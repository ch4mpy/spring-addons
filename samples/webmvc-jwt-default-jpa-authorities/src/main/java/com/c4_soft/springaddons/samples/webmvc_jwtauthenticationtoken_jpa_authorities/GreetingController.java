package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {
	private final MessageService messageService;

	public GreetingController(MessageService messageService) {
		this.messageService = messageService;
	}

	@GetMapping("/greet")
	public String greet(JwtAuthenticationToken auth) {
		return messageService.greet(auth);
	}

	@GetMapping("/secured-route")
	public String securedRoute() {
		return messageService.getSecret();
	}

	@GetMapping("/secured-method")
	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	public String securedMethod() {
		return messageService.getSecret();
	}

	@GetMapping("/claims")
	public Map<String, Object> getClaims(JwtAuthenticationToken auth) {
		return auth.getTokenAttributes();
	}
}
