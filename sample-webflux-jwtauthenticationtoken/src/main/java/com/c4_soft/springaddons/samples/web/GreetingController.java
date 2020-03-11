package com.c4_soft.springaddons.samples.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

@RestController
public class GreetingController {
	private final MessageService messageService;

	@Autowired
	public GreetingController(MessageService messageService) {
		this.messageService = messageService;
	}

	@GetMapping("/greet")
	public Mono<ResponseEntity<String>> greet(Authentication auth) {
		return messageService.greet(auth).map(msg -> ResponseEntity.ok(msg));
	}

	@GetMapping("/secured-service")
	public Mono<ResponseEntity<String>> securedService() {
		return messageService.getSecret().map(msg -> ResponseEntity.ok(msg));
	}

	@GetMapping("/secured-endpoint")
	public Mono<ResponseEntity<String>> securedRoute() {
		return response("secret route");
	}

	@GetMapping("/secured-method")
	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	public Mono<ResponseEntity<String>> securedMethod() {
		return response("secret method");
	}

	private static Mono<ResponseEntity<String>> response(String msg) {
		return Mono.just(ResponseEntity.ok(msg));
	}
}
