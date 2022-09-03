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
package com.c4_soft.springaddons.security.oauth2;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.util.StringUtils;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * @author     ch4mp
 * @param  <T> OpenidClaimSet or any specialization. See {@link }
 */
@Data
@EqualsAndHashCode(callSuper = true)
public class OAuthentication<T extends Map<String, Object> & Serializable> extends AbstractAuthenticationToken implements OAuth2AuthenticatedPrincipal {
	private static final long serialVersionUID = -2827891205034221389L;

	private final T claims;

	private final String tokenString;

	/**
	 * @param claims      claim-set of any-type
	 * @param authorities
	 * @param tokenString base64 encoded JWT string (in case resource-server needs to forward user ID to secured micro-services)
	 */
	public OAuthentication(T claims, Collection<? extends GrantedAuthority> authorities, String tokenString) {
		super(authorities);
		this.claims = claims;
		this.setAuthenticated(true);
		setDetails(claims);
		this.tokenString = Optional.ofNullable(tokenString).map(ts -> ts.toLowerCase().startsWith("bearer ") ? ts.substring(7) : ts).orElse(null);
	}

	public OAuthentication(T claims, Converter<T, Collection<? extends GrantedAuthority>> authoritiesConverter, String tokenString) {
		this(claims, authoritiesConverter.convert(claims), tokenString);
	}

	@Override
	public T getCredentials() {
		return getAttributes();
	}

	@Override
	public T getPrincipal() {
		return getAttributes();
	}

	@Override
	public T getDetails() {
		return getAttributes();
	}

	public String getBearerHeader() {
		if (!StringUtils.hasText(tokenString)) {
			return null;
		}
		return String.format("Bearer %s", tokenString);
	}

	@Override
	public T getAttributes() {
		return claims;
	}

}