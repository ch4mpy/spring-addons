package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Repository;

@Repository
public class SecretRepo {
	@PreAuthorize("authentication.name eq #a0")
	public String findSecretByUsername(String username) {
		return "Don't ever tell it";
	}
}