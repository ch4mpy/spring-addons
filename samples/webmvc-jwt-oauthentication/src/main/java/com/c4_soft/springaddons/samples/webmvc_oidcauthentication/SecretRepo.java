package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Repository;

@Repository
public class SecretRepo {
	@PreAuthorize("authentication.name eq #username")
	public String findSecretByUsername(String username) {
		return "Don't ever tell it";
	}
}