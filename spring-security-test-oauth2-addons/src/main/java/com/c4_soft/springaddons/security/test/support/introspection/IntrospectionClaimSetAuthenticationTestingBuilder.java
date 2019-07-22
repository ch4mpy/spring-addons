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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4_soft.springaddons.security.test.support.AuthoritiesConverterNotAMockException;
import com.c4_soft.springaddons.security.test.support.Defaults;

/**
 * Builder with test default values for {@link OAuth2ClaimSetAuthentication}&lt;{@link IntrospectionClaimSet}&gt;
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class IntrospectionClaimSetAuthenticationTestingBuilder<T extends IntrospectionClaimSetAuthenticationTestingBuilder<T>> {
	final IntrospectionClaimSet.Builder<?> claims;

	final Converter<IntrospectionClaimSet, Set<GrantedAuthority>> authoritiesConverter;

	@Autowired
	public IntrospectionClaimSetAuthenticationTestingBuilder(Converter<IntrospectionClaimSet, Set<GrantedAuthority>> authoritiesConverter) {
		super();
		this.claims = IntrospectionClaimSet.builder().username(Defaults.AUTH_NAME).subject(Defaults.SUBJECT);
		this.authoritiesConverter = authoritiesConverter;
	}

	public T claims(Consumer<IntrospectionClaimSet.Builder<?>> claimsConsumer) {
		claimsConsumer.accept(this.claims);
		return downcast();
	}

	public T name(String username) {
		this.claims.username(username);
		return downcast();
	}

	public T authorities(Stream<String> authorities) {
		final Set<GrantedAuthority> grantedAuthorities = authorities
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());

		try {
			when(authoritiesConverter.convert(any())).thenReturn(grantedAuthorities);
		} catch(RuntimeException e) {
			throw new AuthoritiesConverterNotAMockException();
		}
		return downcast();
	}

	public T authorities(String... authorities) {
		return authorities(Stream.of(authorities));
	}

	public OAuth2ClaimSetAuthentication<IntrospectionClaimSet> build() {
		return new OAuth2ClaimSetAuthentication<>(claims.build(), authoritiesConverter);
	}

	@SuppressWarnings("unchecked")
	protected T downcast() {
		return (T) this;
	}

}
