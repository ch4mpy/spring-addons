package com.c4_soft.springaddons.samples.webmvc.custom;

import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;

@RestController
@RequestMapping("/greet")
@PreAuthorize("isAuthenticated")
public class GreetController {

	@GetMapping
	public String greet(OidcAuthentication<CustomOidcToken> auth, @RequestParam String proxiedUserSubject) {
		return String
				.format(
						"Hello %s, here are the IDs of the grants you were given by user with subject %s: %s",
						auth.getToken().getPreferredUsername(),
						proxiedUserSubject,
						auth.getToken().getGrantIdsOnBehalfOf(proxiedUserSubject).stream().map(Object::toString).collect(Collectors.joining(", ", "[", "]")));
	}

}
