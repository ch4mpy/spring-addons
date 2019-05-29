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
package com.c4soft.springaddons.security.test.support.jwt;

import java.util.function.Consumer;

import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2Authentication;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.ClaimGrantedAuthoritiesService;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;
import com.c4soft.springaddons.security.test.support.Defaults;

/**
 * Builder with test default values for {@link OAuth2Authentication}&lt;{@link WithAuthoritiesJwtClaimSet}&gt;
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class JwtClaimSetAuthenticationTestingBuilder {
	final WithAuthoritiesJwtClaimSet.Builder<?> claims;

	public JwtClaimSetAuthenticationTestingBuilder(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
		super();
		this.claims = WithAuthoritiesJwtClaimSet.builder().subject(Defaults.AUTH_NAME).authorities(Defaults.AUTHORITIES);
		claimsConsumer.accept(this.claims);
	}

	public OAuth2Authentication<WithAuthoritiesJwtClaimSet> build() {
		return new OAuth2Authentication<>(claims.build(), new ClaimGrantedAuthoritiesService());
	}

}
