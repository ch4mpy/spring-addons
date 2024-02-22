package com.c4soft.springaddons.tutorials;

import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/greet")
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE')")
	public String getGreeting(ProxiesAuthentication auth) {
		return "Hi %s! You are granted with: %s and can proxy: %s.".formatted(
				auth.getName(),
				auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")),
				auth.getClaims().getProxies().keySet().stream().collect(Collectors.joining(", ", "[", "]")));
	}

	@GetMapping("/public")
	public String getPublicGreeting() {
		return "Hello world";
	}

	@GetMapping("/on-behalf-of/{username}")
	@PreAuthorize("is(#username) or isNice() or onBehalfOf(#username).can('greet')")
	public String getGreetingFor(@PathVariable(name = "username") String username, Authentication auth) {
		return "Hi %s from %s!".formatted(username, auth.getName());
	}

}
