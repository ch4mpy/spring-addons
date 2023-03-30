package com.c4soft.springaddons.tutorials;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import reactor.core.publisher.Mono;

@Controller
public class ServletClientController {

	@GetMapping("/")
	public Mono<String> getIndex(Authentication auth, Model model) {
		model.addAttribute("isAuthenticated", auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken));
		return Mono.just("index");
	}
}
