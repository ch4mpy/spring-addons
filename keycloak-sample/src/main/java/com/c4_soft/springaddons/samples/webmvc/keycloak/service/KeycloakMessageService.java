package com.c4_soft.springaddons.samples.webmvc.keycloak.service;

import java.util.stream.Collectors;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service
public class KeycloakMessageService implements MessageService {

	@Override
	public String getSecret() {
		return "Secret message";
	}

	@Override
	public String greet(KeycloakAuthenticationToken who) {
		return String.format(
				"Hello %s! You are granted with %s.",
				who.getName(),
				who.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
	}

}