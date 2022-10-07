package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
public class GreetingController {
	private final MessageService messageService;

	@GetMapping("/greet")
	public Mono<ResponseEntity<String>> greet(BearerTokenAuthentication auth) {
		return messageService.greet(auth).map(ResponseEntity::ok);
	}

	@GetMapping("/secured-route")
	public Mono<ResponseEntity<String>> securedRoute() {
		return messageService.getSecret().map(ResponseEntity::ok);
	}

	@GetMapping("/secured-method")
	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	public Mono<ResponseEntity<String>> securedMethod() {
		return messageService.getSecret().map(ResponseEntity::ok);
	}

	@GetMapping("/claims")
	public Mono<ResponseEntity<Map<String, Object>>> getClaims(BearerTokenAuthentication auth) {
		return Mono.just(auth.getTokenAttributes()).map(ResponseEntity::ok);
	}
}
