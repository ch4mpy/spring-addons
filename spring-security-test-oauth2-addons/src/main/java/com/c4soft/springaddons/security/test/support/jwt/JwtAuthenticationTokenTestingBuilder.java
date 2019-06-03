/*
 * Copyright 2019 Jérôme Wacongne.
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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import com.c4soft.springaddons.security.test.support.Defaults;
import com.c4soft.springaddons.security.test.support.missingpublicapi.JwtAuthenticationTokenBuilder;
import com.c4soft.springaddons.security.test.support.missingpublicapi.JwtBuilder;

/**
 * Builder with test default values for {@link JwtAuthenticationToken}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @see JwtAuthenticationToken
 * @see JwtBuilder
 */
public class JwtAuthenticationTokenTestingBuilder<T extends JwtAuthenticationTokenTestingBuilder<T>> extends JwtAuthenticationTokenBuilder<T> {

	private final Set<GrantedAuthority> addedAuthorities;

	/**
	 * @param authoritiesConverter used to extract authorities from the token
	 */
	public JwtAuthenticationTokenTestingBuilder(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		super(new JwtTestingBuilder(), authoritiesConverter);
		this.addedAuthorities = new HashSet<>();
		scopes(Defaults.SCOPES);
	}

	public JwtAuthenticationTokenTestingBuilder() {
		this(new JwtGrantedAuthoritiesConverter());
	}

	@Override
	public JwtAuthenticationToken build() {
		final Jwt token = jwt.build();

		return new JwtAuthenticationToken(token, getAuthorities(token));
	}

	@Override
	protected Collection<GrantedAuthority> getAuthorities(Jwt token) {
		final Collection<GrantedAuthority> tokenAuthorities = super.getAuthorities(token);

		return addedAuthorities.isEmpty() ? tokenAuthorities
				: Stream.concat(tokenAuthorities.stream(), addedAuthorities.stream()).collect(Collectors.toSet());
	}
}
