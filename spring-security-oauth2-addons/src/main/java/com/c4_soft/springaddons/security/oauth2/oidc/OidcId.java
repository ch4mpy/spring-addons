package com.c4_soft.springaddons.security.oauth2.oidc;

import java.security.Principal;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;

import com.c4_soft.springaddons.security.oauth2.UnmodifiableClaimSet;

public class OidcId extends UnmodifiableClaimSet implements IdTokenClaimAccessor, StandardClaimAccessor, Principal {

	public OidcId(Map<String, Object> claims) {
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
