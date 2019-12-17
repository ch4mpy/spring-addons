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
package com.c4_soft.springaddons.test.security.support.jwt;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.oauth2.UnmodifiableClaimSet;
import com.c4_soft.oauth2.rfc7519.JwtRegisteredClaimNames;
import com.c4_soft.springaddons.test.security.support.ClaimSetAuthenticationTestingBuilder;
import com.c4_soft.springaddons.test.security.support.Defaults;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class JwtClaimSetAuthenticationTestingBuilder<C extends UnmodifiableClaimSet & Principal, T extends JwtClaimSetAuthenticationTestingBuilder<C, T>>
		extends
		ClaimSetAuthenticationTestingBuilder<C, T> {

	@Autowired
	public JwtClaimSetAuthenticationTestingBuilder(
			Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter,
			Converter<Map<String, Object>, C> claimsExtractor) {
		super(authoritiesConverter, claimsExtractor);
		name(Defaults.AUTH_NAME);
	}

	public T name(String name) {
		this.claims.put(JwtRegisteredClaimNames.SUBJECT.value, name);
		return downcast();
	}
}
