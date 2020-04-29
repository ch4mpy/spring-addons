package com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.service;

import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
public class JwtAuthenticationTokenMessageService implements MessageService {

	@Override
	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	public String getSecret() {
		return "Secret message";
	}

	@Override
	@PreAuthorize("authenticated")
	public String greet(JwtAuthenticationToken who) {
		return String.format(
				"Hello %s! You are granted with %s.",
				who.getName(),
				who.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
	}

}