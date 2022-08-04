package com.c4_soft.springaddons.security.oauth2.config;

public class MissingAuthorizationServerConfigurationException extends RuntimeException {
	private static final long serialVersionUID = 5189849969622154264L;

	public MissingAuthorizationServerConfigurationException(String jwtIssuer) {
		super(String.format("Missing authorities mapping configuration for issuer: %s", jwtIssuer));
	}

}
