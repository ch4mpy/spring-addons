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

package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.util.Collection;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.AuthenticationBuilder;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder;
import com.c4_soft.springaddons.security.oauth2.test.Defaults;

public class OidcIdAuthenticationTokenWebTestClientConfigurer
		implements
		AuthenticationBuilder<OidcIdAuthenticationToken>,
		AuthenticationConfigurer<OidcIdAuthenticationToken> {

	private final OidcIdBuilder tokenBuilder =
			new OidcIdBuilder().subject(Defaults.SUBJECT).preferredUsername(Defaults.AUTH_NAME);
	private Collection<GrantedAuthority> grantedAuthorities = Defaults.GRANTED_AUTHORITIES;

	public OidcIdAuthenticationTokenWebTestClientConfigurer token(Consumer<OidcIdBuilder> oidcIdTokenConsumer) {
		oidcIdTokenConsumer.accept(tokenBuilder);
		return this;
	}

	public OidcIdAuthenticationTokenWebTestClientConfigurer authorities(String... authorities) {
		grantedAuthorities = Stream.of(authorities).map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
		return this;
	}

	@Override
	public OidcIdAuthenticationToken build() {
		return new OidcIdAuthenticationToken(tokenBuilder.build(), grantedAuthorities);
	}

	public static OidcIdAuthenticationTokenWebTestClientConfigurer oidcId() {
		return new OidcIdAuthenticationTokenWebTestClientConfigurer();
	}
}