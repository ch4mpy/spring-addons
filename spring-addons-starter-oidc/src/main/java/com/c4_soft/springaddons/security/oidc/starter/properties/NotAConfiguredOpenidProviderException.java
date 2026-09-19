package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Thrown when the claims of a token can't be mapped to any configured OpenID Provider.
 * <p>
 * This is an {@link OAuth2AuthenticationException}, so that when thrown from an authentication manager or an authentication converter, Spring Security
 * answers with a {@code 401} instead of letting a {@code 500} escape the security filter-chain.
 * </p>
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class NotAConfiguredOpenidProviderException extends OAuth2AuthenticationException {
	private static final long serialVersionUID = 5189849969622154264L;

	public NotAConfiguredOpenidProviderException(Map<String, Object> claims) {
		super(
				new OAuth2Error(
						OAuth2ErrorCodes.INVALID_TOKEN,
						"Could not resolve OpenID Provider configuration properties from a JWT with %s as issuer and %s as audience"
								.formatted(claims.get("iss"), claims.get("aud")),
						null));
	}

}
