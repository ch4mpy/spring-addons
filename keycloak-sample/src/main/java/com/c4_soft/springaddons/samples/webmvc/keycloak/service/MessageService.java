package com.c4_soft.springaddons.samples.webmvc.keycloak.service;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.access.prepost.PreAuthorize;

public interface MessageService {

	@PreAuthorize("hasAuthority('AUTHORIZED_PERSONNEL')")
	String getSecret();

	@PreAuthorize("authenticated")
	String greet(KeycloakAuthenticationToken who);

}
