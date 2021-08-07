package com.c4_soft.springaddons.security.oauth2.oidc;

import java.io.Serializable;
import java.security.Principal;
import java.util.Map;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;

import com.c4_soft.springaddons.security.oauth2.UnmodifiableClaimSet;

public class IdToken extends UnmodifiableClaimSet implements IdTokenClaimAccessor, Principal {
	private static final long serialVersionUID = 5760410336175406391L;

	public <T extends Map<String, Object> & Serializable> IdToken(T claims) {
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
