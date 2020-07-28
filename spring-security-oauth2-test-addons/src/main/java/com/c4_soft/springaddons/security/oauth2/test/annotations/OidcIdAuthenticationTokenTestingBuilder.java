/*
 * Copyright 2020 Jérôme Wacongne.
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
package com.c4_soft.springaddons.security.oauth2.test.annotations;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.AuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder;
import com.c4_soft.springaddons.security.oauth2.test.Defaults;

public class OidcIdAuthenticationTokenTestingBuilder<T extends OidcIdAuthenticationTokenTestingBuilder<T>>
		implements
		AuthenticationBuilder<OidcIdAuthenticationToken> {

	protected final OidcIdBuilder tokenBuilder;
	private final Set<String> authorities;

	public OidcIdAuthenticationTokenTestingBuilder() {
		super();
		this.tokenBuilder = new OidcIdBuilder().name(Defaults.AUTH_NAME);
		this.authorities = new HashSet<>(Arrays.asList(Defaults.AUTHORITIES));
	}

	@Override
	public OidcIdAuthenticationToken build() {
		return new OidcIdAuthenticationToken(
				tokenBuilder.build(),
				authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()));
	}

	public T authorities(String... authorities) {
		this.authorities.clear();
		this.authorities.addAll(Arrays.asList(authorities));
		return downcast();
	}

	public T token(Consumer<OidcIdBuilder> tokenBuilderConsumer) {
		tokenBuilderConsumer.accept(tokenBuilder);
		return downcast();
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}
}