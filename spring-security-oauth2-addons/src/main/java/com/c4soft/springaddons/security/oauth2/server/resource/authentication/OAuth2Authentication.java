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
package com.c4soft.springaddons.security.oauth2.server.resource.authentication;

import java.security.Principal;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.c4soft.oauth2.ClaimSet;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class OAuth2Authentication<T extends ClaimSet & Principal> extends AbstractAuthenticationToken {
	private static final long serialVersionUID = -4587252869458137355L;

	private OAuth2Authentication(T principal, Collection<GrantedAuthority> authorities) {
		super(authorities);
		setDetails(principal);
		setAuthenticated(true);
	}

	public OAuth2Authentication(T claims, PrincipalGrantedAuthoritiesService authoritiesService) {
		this(claims, authoritiesService.getAuthorities(claims));
	}

	public T getClaims() {
		return getDetails();
	}

	@Override
	public String getName() {
		return getDetails().getName();
	}

	@Override
	public T getCredentials() {
		return getDetails();
	}

	@SuppressWarnings("unchecked")
	@Override
	public T getDetails() {
		return (T) super.getDetails();
	}

	@Override
	public T getPrincipal() {
		return getDetails();
	}
}
