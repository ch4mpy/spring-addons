/*
 * Copyright 2020 Jérôme Wacongne
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
package com.c4_soft.springaddons.security.oauth2.keycloak;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdAuthenticationToken;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcIdBuilder;

public class KeycloakOidcIdAuthenticationConverter implements Converter<Jwt, OidcIdAuthenticationToken> {

	private final Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

	public KeycloakOidcIdAuthenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		super();
		this.authoritiesConverter = authoritiesConverter;
	}

	@Override
	public OidcIdAuthenticationToken convert(Jwt jwt) {
		final var token = new OidcIdBuilder(jwt.getClaims()).build();
		return new OidcIdAuthenticationToken(token, authoritiesConverter.convert(jwt));
	}
}
