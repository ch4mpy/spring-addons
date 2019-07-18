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

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;

import com.c4_soft.springaddons.security.test.support.AuthoritiesConverterNotAMockException;
import com.c4_soft.springaddons.security.test.support.missingpublicapi.OAuth2IntrospectionAuthenticationTokenBuilder;

/**
 * Builder with test default values for {@link OAuth2IntrospectionAuthenticationToken}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2IntrospectionAuthenticationTokenTestingBuilder<T extends OAuth2IntrospectionAuthenticationTokenTestingBuilder<T>>
		extends OAuth2IntrospectionAuthenticationTokenBuilder<T> {

	public OAuth2IntrospectionAuthenticationTokenTestingBuilder(
			Converter<Map<String, Object>, Collection<GrantedAuthority>> authoritiesConverter) {
		super(authoritiesConverter, new OAuth2IntrospectionTokenTestingBuilder());
	}

	/**
	 * /!\ To be called only if authorities converter is a mock /!\
	 * Configure JWT for converter to return expected authorities otherwise
	 * @param authorities granted authorities to mock
	 * @return this builder to further configure
	 * @throws AuthoritiesConverterNotAMockException
	 */
	public T authorities(Stream<String> authorities) {
		final Collection<GrantedAuthority> grantedAuthorities = authorities
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());

		try {
			when(authoritiesConverter.convert(any())).thenReturn(grantedAuthorities);
		} catch(RuntimeException e) {
			throw new AuthoritiesConverterNotAMockException();
		}

		return downcast();
	}

	/**
	 * /!\ To be called only if authorities converter is a mock /!\
	 * Configure JWT for converter to return expected authorities otherwise
	 * @param authorities granted authorities to mock
	 * @return this builder to further configure
	 * @throws AuthoritiesConverterNotAMockException
	 */
	public T authorities(String... authorities) {
		return authorities(Stream.of(authorities));
	}

}
