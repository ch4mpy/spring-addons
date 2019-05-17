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
package org.springframework.security.test.support.missingpublicapi;

import java.util.Collection;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.support.AuthenticationBuilder;

/**
 * Helps configure a {@link JwtAuthenticationToken}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 *
 * @see JwtAuthenticationToken
 * @see JwtBuilder
 */
public class JwtAuthenticationTokenBuilder<T extends JwtAuthenticationTokenBuilder<T>> implements AuthenticationBuilder<JwtAuthenticationToken> {

	private final Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

	protected final JwtBuilder<?> jwt;

	@Autowired
	public JwtAuthenticationTokenBuilder(JwtBuilder<?> jwtBuilder, Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		this.authoritiesConverter = authoritiesConverter;
		this.jwt = jwtBuilder;
	}

	@Autowired
	public JwtAuthenticationTokenBuilder(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		this(new JwtBuilder<>(), authoritiesConverter);
	}

	public T token(Consumer<JwtBuilder<?>> jwtBuilderConsumer) {
		jwtBuilderConsumer.accept(jwt);
		return downcast();
	}

	public T name(String name) {
		jwt.subject(name);
		return downcast();
	}

	public T claim(String name, Object value) {
		jwt.claim(name, value);
		return downcast();
	}

	/**
	 * Shortcut to set "scope" claim with a space separated string containing provided scope collection
	 * @param scopes strings to join with spaces and set as "scope" claim
	 * @return this builder to further configure
	 */
	public T scopes(String... scopes) {
		jwt.claim("scope", Stream.of(scopes).collect(Collectors.joining(" ")));
		return downcast();
	}

	public T subject(String subject) {
		jwt.subject(subject);
		return downcast();
	}

	@Override
	public JwtAuthenticationToken build() {
		final Jwt token = jwt.build();
		return new JwtAuthenticationToken(token, authoritiesConverter.convert(token));
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}
	
	protected Collection<GrantedAuthority> getAuthorities(Jwt token) {
		return authoritiesConverter.convert(token);
	}
}
