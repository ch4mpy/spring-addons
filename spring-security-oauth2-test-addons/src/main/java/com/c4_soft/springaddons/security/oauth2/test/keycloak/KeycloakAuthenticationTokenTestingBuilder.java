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
package com.c4_soft.springaddons.security.oauth2.test.keycloak;

import java.util.Collection;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;

import com.c4_soft.springaddons.security.oauth2.test.Defaults;

/**
 * Builder with test default values for {@link KeycloakAuthenticationToken}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @see KeycloakAuthenticationToken
 * @see KeycloakAuthenticationTokenBuilder
 */
public class KeycloakAuthenticationTokenTestingBuilder<T extends KeycloakAuthenticationTokenTestingBuilder<T>>
		extends
		KeycloakAuthenticationTokenBuilder<T> {

	private KeycloakDeployment keycloakDeployment = null;

	private final AccessToken accessToken = new AccessToken();
	private String accessTokenString = "test.keycloak.token";
	private IDToken idToken = null;
	private String idTokenString = null;
	private String refreshTokenString = null;

	private final GrantedAuthoritiesMapper authoritiesMapper;

	public KeycloakAuthenticationTokenTestingBuilder(Optional<GrantedAuthoritiesMapper> authoritiesMapper) {
		super();
		this.authoritiesMapper = authoritiesMapper.orElse(new NullAuthoritiesMapper());

		this.accessToken.setRealmAccess(new AccessToken.Access());
		this.accessToken.setPreferredUsername(Defaults.AUTH_NAME);
		this.authorities("offline_access", "uma_authorization");
	}

	public void keycloakDeployment(KeycloakDeployment keycloakDeployment) {
		this.keycloakDeployment = keycloakDeployment;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public T authorities(Stream<String> authorities) {
		final var authoritiesSet = authorities.collect(Collectors.toSet());
		this.accessToken.getRealmAccess().roles(authoritiesSet);
		super.authorities(
				(Collection) authoritiesMapper.mapAuthorities(
						authoritiesSet.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet())));
		return downcast();
	}

	public T authorities(String... authorities) {
		return this.authorities(Stream.of(authorities));
	}

	public T accessToken(Consumer<AccessToken> token) {
		token.accept(this.accessToken);
		return downcast();
	}

	public T idToken(Consumer<IDToken> token) {
		if (this.idToken == null) {
			this.idToken = new IDToken();
		}
		token.accept(this.idToken);
		return downcast();
	}

	public T idToken(IDToken token) {
		this.idToken = token;
		return downcast();
	}

	public T tokenString(String tokenString) {
		this.accessTokenString = tokenString;
		return downcast();
	}

	public T idTokenString(String idTokenString) {
		this.idTokenString = idTokenString;
		return downcast();
	}

	public T refreshTokenString(String refreshTokenString) {
		this.refreshTokenString = refreshTokenString;
		return downcast();
	}

	@Override
	public KeycloakAuthenticationToken build() {
		final var securityContext = new RefreshableKeycloakSecurityContext(
				keycloakDeployment,
				null,
				accessTokenString,
				accessToken,
				idTokenString == null ? accessTokenString : idTokenString,
				idToken == null ? accessToken : idToken,
				refreshTokenString);

		final var principal = new KeycloakPrincipal<>(accessToken.getPreferredUsername(), securityContext);

		final var account =
				new SimpleKeycloakAccount(principal, accessToken.getRealmAccess().getRoles(), securityContext);

		return new KeycloakAuthenticationToken(account, isInteractive, authorities);
	}
}
