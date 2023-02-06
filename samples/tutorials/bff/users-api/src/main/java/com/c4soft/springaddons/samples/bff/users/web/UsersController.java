package com.c4soft.springaddons.samples.bff.users.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;

@RestController
@RequestMapping("/users")
public class UsersController {

	@GetMapping("/me")
	public OpenidClaimSet getClaims(OAuthentication<OpenidClaimSet> auth) {
		return auth.getAttributes(); 
	}
}
