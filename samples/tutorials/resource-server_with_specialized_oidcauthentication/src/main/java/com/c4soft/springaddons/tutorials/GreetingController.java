package com.c4soft.springaddons.tutorials;

import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated()")
public class GreetingController {

	@GetMapping()
	@PreAuthorize("hasAuthority('NICE_GUY')")
	public String getGreeting(MyAuthentication auth) {
		return String
				.format(
						"Hi %s! You are granted with: %s and can proxy: %s.",
						auth.getToken().getPreferredUsername(),
						auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(", ", "[", "]")),
						auth.getProxies().keySet().stream().collect(Collectors.joining(", ", "[", "]")));
	}

	@GetMapping("/{otherSubject}")
	@PreAuthorize("isNice() or onBehalfOf(#otherSubject).can('greet')")
	public String getGreetingFor(@PathVariable("otherSubject") String otherSubject) {
		return String.format("Hi %s!", otherSubject);
	}
}
