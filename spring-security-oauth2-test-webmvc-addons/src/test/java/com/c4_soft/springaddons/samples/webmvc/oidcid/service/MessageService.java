package com.c4_soft.springaddons.samples.webmvc.oidcid.service;

import org.springframework.security.access.prepost.PreAuthorize;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;

public interface MessageService {

	@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	String getSecret();

	@PreAuthorize("authenticated")
	String greet(OidcIdAuthenticationToken who);

}
