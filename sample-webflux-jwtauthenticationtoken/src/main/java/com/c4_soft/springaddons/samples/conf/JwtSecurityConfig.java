/*
 * Copyright 2019 Jérôme Wacongne
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
package com.c4_soft.springaddons.samples.conf;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import net.minidev.json.JSONArray;
import reactor.core.publisher.Mono;

@Configuration
public class JwtSecurityConfig {

	@Bean
	Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter() {
		return new KeycloackAuthoritiesConverter();
	}

	@Bean
	Converter<Jwt, Mono<AbstractAuthenticationToken>>
			authenticationConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		return new JwtAuthenticationTokenConverter(authoritiesConverter);
	}

	public static class KeycloackAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
		@Override
		public Collection<GrantedAuthority> convert(Jwt source) {
			final var realmAccess = source.getClaimAsMap("realm_access");
			final var roles = (JSONArray) (realmAccess == null ? new JSONArray() : realmAccess.get("roles"));
			return roles.stream()
					.map(Object::toString)
					.map(role -> new SimpleGrantedAuthority("ROLE_" + role))
					.collect(Collectors.toSet());
		}
	}

	static class JwtAuthenticationTokenConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {
		private final Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

		@Autowired
		public JwtAuthenticationTokenConverter(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
		}

		@Override
		public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
			return Mono.just(
					new JwtAuthenticationToken(
							jwt,
							authoritiesConverter.convert(jwt),
							jwt.getClaimAsString(StandardClaimNames.PREFERRED_USERNAME)));
		}
	}

}