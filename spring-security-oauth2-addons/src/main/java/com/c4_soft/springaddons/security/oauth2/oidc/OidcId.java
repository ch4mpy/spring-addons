package com.c4_soft.springaddons.security.oauth2.oidc;

import java.io.Serializable;
import java.util.Map;

public class OidcId extends IdToken {
	@java.io.Serial
	private static final long serialVersionUID = 181590625919385642L;

	public <T extends Map<String, Object> & Serializable> OidcId(T claims) {
		super(claims);
	}

}
