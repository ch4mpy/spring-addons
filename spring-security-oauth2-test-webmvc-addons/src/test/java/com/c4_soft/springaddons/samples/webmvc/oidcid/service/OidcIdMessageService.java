package com.c4_soft.springaddons.samples.webmvc.oidcid.service;

import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;

@Service
public class OidcIdMessageService implements MessageService {

	@Override
	public String getSecret() {
		return "Secret message";
	}

	@Override
	public String greet(OidcAuthentication<?> who) {
		return String.format(
				"Hello %s! You are granted with %s.",
				who.getToken().getPreferredUsername(),
				who.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
	}

}