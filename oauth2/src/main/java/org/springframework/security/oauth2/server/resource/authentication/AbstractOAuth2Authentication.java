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

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.c4soft.oauth2.OAuth2Authorization;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public abstract class AbstractOAuth2Authentication<T extends OAuth2Authorization<ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE>, ACCESS_TOKEN_TYPE, REFRESH_TOKEN_TYPE> implements Authentication {
	private static final long serialVersionUID = -4587252869458137355L;

	private final T authorization;
	private final Collection<GrantedAuthority> authorities;

	protected AbstractOAuth2Authentication(T authorization, Collection<GrantedAuthority> authorities) {
		this.authorization = authorization;
		this.authorities = Collections.unmodifiableCollection(authorities);
	}

	public T getAuthorization() {
		return authorization;
	}

	public ACCESS_TOKEN_TYPE getAccessToken() {
		return authorization.getAccessToken();
	}

	@Override
	public abstract String getName();

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public Object getCredentials() {
		return authorization.getAccessToken();
	}

	@Override
	public Object getDetails() {
		return authorization;
	}

	@Override
	public Object getPrincipal() {
		return authorization;
	}

	@Override
	public boolean isAuthenticated() {
		return authorization != null;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		throw new UnsupportedOperationException("OAuth2Authentication is immutable");
	}
}
