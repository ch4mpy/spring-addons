package com.c4_soft.springaddons.samples.webmvc_keycloakauthenticationtoken;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service
public class MessageService {

	public String getSecret() {
		return "Secret message";
	}

	public String greet(KeycloakAuthenticationToken who) {
		return String
				.format(
						"Hello %s! You are granted with %s.",
						who.getAccount().getKeycloakSecurityContext().getIdToken().getPreferredUsername(),
						who.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
	}

}