/*
 * Copyright 2019 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.test.security.support.keycloak;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.c4_soft.springaddons.test.security.support.AuthenticationBuilder;
import com.c4_soft.springaddons.test.security.support.missingpublicapi.JwtBuilder;

/**
 * Builder for {@link KeycloakAuthenticationToken}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @see JwtAuthenticationToken
 * @see JwtBuilder
 */
public class KeycloakAuthenticationTokenBuilder<T extends KeycloakAuthenticationTokenBuilder<T>>
		implements
		AuthenticationBuilder<KeycloakAuthenticationToken> {

	private OidcKeycloakAccount account;

	protected boolean isInteractive = false;

	protected final Set<GrantedAuthority> authorities = new HashSet<>();

	public T account(OidcKeycloakAccount account) {
		this.account = account;
		return downcast();
	}

	public T isIntercative(boolean isInteractive) {
		this.isInteractive = isInteractive;
		return downcast();
	}

	public T authorities(Collection<GrantedAuthority> authorities) {
		this.authorities.clear();
		this.authorities.addAll(authorities);
		return downcast();
	}

	@Override
	public KeycloakAuthenticationToken build() {

		return new KeycloakAuthenticationToken(account, isInteractive, authorities);
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}
}
