package com.c4_soft.springaddons.security.oauth2.config;

import java.net.URL;

public class MissingAuthorizationServerConfigurationException extends RuntimeException {
	private static final long serialVersionUID = 5189849969622154264L;

	public MissingAuthorizationServerConfigurationException(URL jwtIssuer) {
		super(String.format("Missing authorities mapping configuration for issuer: %s", jwtIssuer.toString()));
	}

}
