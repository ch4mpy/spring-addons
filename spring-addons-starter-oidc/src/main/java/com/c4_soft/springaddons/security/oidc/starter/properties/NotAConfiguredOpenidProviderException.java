package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class NotAConfiguredOpenidProviderException extends RuntimeException {
	private static final long serialVersionUID = 5189849969622154264L;

	public NotAConfiguredOpenidProviderException(Map<String, Object> claims) {
		super(
				"Could not resolve OpenID Provider configuration properties from a JWT with %s as issuer and %s as audience"
						.formatted(claims.get("iss"), claims.get("aud")));
	}

}