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
package org.springframework.security.oauth2.server.resource.authentication;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.c4soft.oauth2.TokenProperties;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class OAuth2Authentication<T extends TokenProperties & Principal> implements Authentication {
	private static final long serialVersionUID = -4587252869458137355L;

	private final T principal;
	private final Set<GrantedAuthority> authorities;

	private OAuth2Authentication(T principal, Collection<GrantedAuthority> authorities) {
		this.principal = principal;
		this.authorities = Collections.unmodifiableSet(new HashSet<>(authorities));
	}

	protected OAuth2Authentication(T claims, PrincipalGrantedAuthoritiesService authoritiesService) {
		this(claims, authoritiesService.getAuthorities(claims));
	}

	public T getAuthorization() {
		return principal;
	}

	public T getClaims() {
		return principal;
	}

	@Override
	public String getName() {
		return principal.getName();
	}

	@Override
	public Set<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public T getCredentials() {
		return principal;
	}

	@Override
	public T getDetails() {
		return principal;
	}

	@Override
	public T getPrincipal() {
		return principal;
	}

	@Override
	public boolean isAuthenticated() {
		return principal != null;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		throw new UnsupportedOperationException("OAuth2Authentication is immutable");
	}
}
