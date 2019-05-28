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
package org.springframework.security.test.support.jwt;

import java.util.function.Consumer;

import org.springframework.security.oauth2.server.resource.authentication.OAuth2Authentication;
import org.springframework.security.oauth2.server.resource.authentication.embedded.AuthoritiesClaimGrantedAuthoritiesService;
import org.springframework.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;
import org.springframework.security.test.support.Defaults;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class JwtClaimSetAuthenticationTestingBuilder {
	final WithAuthoritiesJwtClaimSet.Builder<?> claims;

	public JwtClaimSetAuthenticationTestingBuilder(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
		super();
		this.claims = WithAuthoritiesJwtClaimSet.builder().subject(Defaults.SUBJECT).authorities(Defaults.AUTHORITIES);
		claimsConsumer.accept(this.claims);
	}

	public OAuth2Authentication<WithAuthoritiesJwtClaimSet> build() {
		return new OAuth2Authentication<>(claims.build(), new AuthoritiesClaimGrantedAuthoritiesService());
	}

}
