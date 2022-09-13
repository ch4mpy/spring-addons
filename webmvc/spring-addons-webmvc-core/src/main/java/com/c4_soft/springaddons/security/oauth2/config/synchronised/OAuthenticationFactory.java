/*
 * Copyright 2020 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may
 * obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Turn a JWT into a spring-security Authentication instance.
 * </p>
 * Sample configuration for Keyclkoak, getting roles from "realm_access" claim:
 *
 * <pre>
 * &#64;Bean
 * public SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter() {
 * 	return (var jwt) -&gt; {
 * 		final var roles = Optional.ofNullable((JSONObject) jwt.getClaims().get("realm_access"))
 * 				.flatMap(realmAccess -&gt; Optional.ofNullable((JSONArray) realmAccess.get("roles"))).orElse(new JSONArray());
 * 		return roles.stream().map(Object::toString).map(role -&gt; new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toSet());
 * 	};
 * }
 *
 * &#64;Bean
 * public SynchronizedJwt2OidcIdAuthenticationConverter authenticationConverter(SynchronizedJwt2GrantedAuthoritiesConverter authoritiesConverter) {
 * 	return new SynchronizedJwt2OidcIdAuthenticationConverter(authoritiesConverter);
 * }
 * </pre>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public class OAuthenticationFactory<T extends Map<String, Object> & Serializable> implements OAuth2AuthenticationFactory {

	private final Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter;
	private final Converter<Map<String, Object>, T> claimsConverter;

	@Override
	public AbstractAuthenticationToken build(String bearerString, Map<String, Object> claims) {
		final var claimSet = claimsConverter.convert(claims);
		return new OAuthentication<>(claimSet, authoritiesConverter.convert(claims), bearerString);
	}
}
