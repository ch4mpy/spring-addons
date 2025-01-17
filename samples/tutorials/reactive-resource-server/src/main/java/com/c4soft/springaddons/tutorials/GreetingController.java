package com.c4soft.springaddons.tutorials;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class GreetingController {

	@GetMapping("/greet")
	public Mono<MessageDto> getGreeting(Authentication auth) {
		return Mono.just(new MessageDto("Hi %s! You are granted with: %s.".formatted(auth.getName(), auth.getAuthorities())));
	}

	@GetMapping("/restricted")
	@PreAuthorize("hasAuthority('NICE')")
	public Mono<MessageDto> getRestricted() {
		return Mono.just(new MessageDto("You are so nice!"));
	}

	static record MessageDto(String body) {
	}
}
