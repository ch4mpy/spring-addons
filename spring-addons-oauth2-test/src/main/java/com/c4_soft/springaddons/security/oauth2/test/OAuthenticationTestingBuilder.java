/*
 * Copyright 2020 Jérôme Wacongne.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;

public class OAuthenticationTestingBuilder<T extends OAuthenticationTestingBuilder<T>> implements AuthenticationBuilder<OAuthentication<OpenidClaimSet>> {

	protected final OpenidClaimSetBuilder tokenBuilder;
	private final Set<String> authorities;
	private String bearerString = "machin.truc.chose";

	public OAuthenticationTestingBuilder() {
		this.tokenBuilder = new OpenidClaimSetBuilder().subject(Defaults.SUBJECT).name(Defaults.AUTH_NAME);
		this.authorities = new HashSet<>(Defaults.AUTHORITIES);
	}

	@Override
	public OAuthentication<OpenidClaimSet> build() {
		return new OAuthentication<>(tokenBuilder.build(), authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()), bearerString);
	}

	public T authorities(String... authorities) {
		this.authorities.clear();
		this.authorities.addAll(Arrays.asList(authorities));
		return downcast();
	}

	public T token(Consumer<OpenidClaimSetBuilder> tokenBuilderConsumer) {
		tokenBuilderConsumer.accept(tokenBuilder);
		return downcast();
	}

	public T bearerString(String bearerString) {
		this.bearerString = bearerString;
		return downcast();
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}
}