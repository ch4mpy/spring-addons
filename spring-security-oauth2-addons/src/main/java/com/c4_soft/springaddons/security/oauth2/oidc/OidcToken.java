package com.c4_soft.springaddons.security.oauth2.oidc;

import java.security.Principal;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;

import com.c4_soft.springaddons.security.oauth2.UnmodifiableClaimSet;

public class OidcToken extends UnmodifiableClaimSet implements IdTokenClaimAccessor, Principal {
	private static final long serialVersionUID = -5149299350697429528L;

	public OidcToken(Map<String, Object> claims) {
		super(claims);
	}

	@Override
	public Map<String, Object> getClaims() {
		return this;
	}

	@Override
	public String getName() {
		return getSubject();
	}

}
