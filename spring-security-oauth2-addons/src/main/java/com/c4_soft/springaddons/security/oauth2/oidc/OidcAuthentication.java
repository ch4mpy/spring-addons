/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.oidc;

import java.util.Collection;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * 
 * @author ch4mp
 *
 * @param <T> OidcToken or any specialization. See {@link }
 */
public class OidcAuthentication<T extends OidcToken> extends AbstractAuthenticationToken {
	private static final long serialVersionUID = -2827891205034221389L;

	private final T token;

	private final String authorizationHeader;

	/**
	 * @param token
	 * @param authorities
	 * @param bearerString base64 encoded JWT string
	 */
	public OidcAuthentication(T token, Collection<? extends GrantedAuthority> authorities, String bearerString) {
		super(authorities);
		this.token = token;
		this.setAuthenticated(true);
		setDetails(token);
		this.authorizationHeader = String.format("Bearer %s", bearerString);
	}

	public String getAuthorizationHeader() {
		return authorizationHeader;
	}

	public T getToken() {
		return token;
	}

	@Override
	public T getCredentials() {
		return getToken();
	}

	@Override
	public T getPrincipal() {
		return getToken();
	}

	@Override
	public T getDetails() {
		return getToken();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		final int result = super.hashCode();
		return prime * result + Objects.hash(token);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj) || !(obj instanceof OidcAuthentication)) {
			return false;
		}
		final OidcAuthentication<?> other = (OidcAuthentication<?>) obj;
		return Objects.equals(token, other.token);
	}

}