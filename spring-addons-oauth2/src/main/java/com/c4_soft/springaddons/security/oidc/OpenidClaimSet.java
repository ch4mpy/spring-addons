package com.c4_soft.springaddons.security.oidc;

import java.security.Principal;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import com.jayway.jsonpath.PathNotFoundException;

public class OpenidClaimSet extends UnmodifiableClaimSet implements IdTokenClaimAccessor, Principal {
	private static final long serialVersionUID = -5149299350697429528L;

	/**
	 * JSON path for the claim to use as "name" source
	 */
	private final String usernameClaim;

	public OpenidClaimSet(Map<String, Object> claims, String usernameClaim) {
		super(claims);
		this.usernameClaim = usernameClaim;
	}

	public OpenidClaimSet(Map<String, Object> claims) {
		this(claims, StandardClaimNames.SUB);
	}

	@Override
	public Map<String, Object> getClaims() {
		return this;
	}

	@Override
	public String getName() {
		try {
			return getByJsonPath(usernameClaim);
		} catch (PathNotFoundException e) {
			return getByJsonPath(JwtClaimNames.SUB);
		}
	}

}
