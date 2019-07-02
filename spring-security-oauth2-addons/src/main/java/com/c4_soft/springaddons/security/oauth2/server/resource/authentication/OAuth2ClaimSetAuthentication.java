/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.server.resource.authentication;

import java.security.Principal;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.oauth2.UnmodifiableClaimSet;
import com.c4_soft.oauth2.rfc7519.JwtClaimSet;
import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;

/**
 * {@link Authentication} implementation based on OAuth2 token claim set
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 * @param <T> OAuth2 claim set type
 *
 * @see JwtClaimSet
 * @see IntrospectionClaimSet
 */
public class OAuth2ClaimSetAuthentication<T extends UnmodifiableClaimSet & Principal> extends AbstractAuthenticationToken {
	private static final long serialVersionUID = -4587252869458137355L;

	private final T claimSet;

	private OAuth2ClaimSetAuthentication(T principal, Set<GrantedAuthority> authorities) {
		super(authorities);
		this.claimSet = principal;
		setDetails(principal);
		setAuthenticated(true);
	}

	public OAuth2ClaimSetAuthentication(T claims, Converter<T, Set<GrantedAuthority>> authoritiesConverter) {
		this(claims, authoritiesConverter.convert(claims));
	}

	@Override
	public String getName() {
		return claimSet.getName();
	}

	@Override
	public T getCredentials() {
		return null;
	}

	public T getClaimSet() {
		return claimSet;
	}

	@Override
	public T getPrincipal() {
		return claimSet;
	}
}
