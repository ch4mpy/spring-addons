package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Repository;

@Repository
public class SecretRepo {
	@PreAuthorize("authentication.tokenAttributes['preferred_username'] eq #username")
	public String findSecretByUsername(String username) {
		return "Don't ever tell it";
	}
}