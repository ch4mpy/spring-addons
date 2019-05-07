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
package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Slightly more configurable than {@link JwtGrantedAuthoritiesConverter}.
 *
 * Usage:
 * <pre>
 * jwtConfigurer.jwtAuthenticationConverter(new JwtClaimsAuthoritiesConverter(new TokenAttributesAuthoritiesConverter("scope")));
 * </pre>
 *
 * @see StringCollectionAuthoritiesConverter
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class JwtClaimsAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	private final Converter<Map<String, Object>, Collection<GrantedAuthority>> claimsConverter;

	@Autowired
	public JwtClaimsAuthoritiesConverter(Converter<Map<String, Object>, Collection<GrantedAuthority>> claimsConverter) {
		this.claimsConverter = claimsConverter;
	}

	@Override
	public Collection<GrantedAuthority> convert(Jwt source) {
		return claimsConverter.convert(source.getClaims());
	}

	public static JwtClaimsAuthoritiesConverter sameAsSpringSecurity() {
		return new JwtClaimsAuthoritiesConverter(new AttributesToStringCollectionToAuthoritiesConverter(
				TokenAttributesStringListConverter.builder().build(),
				new StringCollectionAuthoritiesConverter("SCOPE_")));
	}

	public static JwtClaimsAuthoritiesConverter fromScopesNoPrefix() {
		return new JwtClaimsAuthoritiesConverter(new AttributesToStringCollectionToAuthoritiesConverter(
				TokenAttributesStringListConverter.builder().build(),
				new StringCollectionAuthoritiesConverter()));
	}

}
