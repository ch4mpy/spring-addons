package com.c4_soft.springaddons.samples.webmvc.jwtauthenticationtoken.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public interface MessageService {

	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	String getSecret();

	@PreAuthorize("authenticated")
	String greet(JwtAuthenticationToken who);

}
