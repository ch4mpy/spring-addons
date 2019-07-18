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
package com.c4_soft.springaddons.security.test.support.introspection;

import java.util.function.Consumer;

import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.AuthoritiesClaim2GrantedAuthoritySetConverter;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import com.c4_soft.springaddons.security.test.support.Defaults;

/**
 * Builder with test default values for {@link OAuth2ClaimSetAuthentication}&lt;{@link WithAuthoritiesIntrospectionClaimSet}&gt;
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class IntrospectionClaimSetAuthenticationTestingBuilder {
	final WithAuthoritiesIntrospectionClaimSet.Builder<?> claims;

	public IntrospectionClaimSetAuthenticationTestingBuilder() {
		super();
		this.claims = WithAuthoritiesIntrospectionClaimSet.builder().subject(Defaults.AUTH_NAME).authorities(Defaults.AUTHORITIES);
	}

	public IntrospectionClaimSetAuthenticationTestingBuilder(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
		this();
		claimsConsumer.accept(this.claims);
	}

	public IntrospectionClaimSetAuthenticationTestingBuilder claims(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
		claimsConsumer.accept(this.claims);
		return this;
	}

	public OAuth2ClaimSetAuthentication<WithAuthoritiesIntrospectionClaimSet> build() {
		return new OAuth2ClaimSetAuthentication<>(claims.build(), new AuthoritiesClaim2GrantedAuthoritySetConverter<>());
	}

}
