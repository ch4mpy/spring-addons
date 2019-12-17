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

package com.c4_soft.springaddons.test.security.context.support;

import java.lang.annotation.Annotation;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import com.c4_soft.oauth2.UnmodifiableClaimSet;
import com.c4_soft.springaddons.security.oauth2.server.resource.authentication.OAuth2ClaimSetAuthentication;
import com.c4_soft.springaddons.test.security.support.ClaimSetAuthenticationTestingBuilder;
import com.c4_soft.springaddons.test.security.support.Defaults;

/**
 *
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public abstract class AbstractWithClaimSetFactory<A extends Annotation, C extends UnmodifiableClaimSet & Principal>
		implements
		WithSecurityContextFactory<A> {

	private final Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter;

	private final ClaimSetAuthenticationTestingBuilder<C, ?> authBuilder;

	public AbstractWithClaimSetFactory(
			Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter,
			ClaimSetAuthenticationTestingBuilder<C, ?> authBuilder) {
		this.authoritiesConverter = authoritiesConverter;
		this.authBuilder = authBuilder;
	}

	@Override
	public SecurityContext createSecurityContext(A annotation) {
		final SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication(annotation));

		return context;
	}

	protected OAuth2ClaimSetAuthentication<C> authentication(A annotation) {
		authBuilder.claims(claims -> claims.putAll(claimsMap(annotation)));

		final var overridenAuthorities = authoritiesOverride(annotation);
		if (overridenAuthorities.length > 0) {
			authBuilder.authorities(overridenAuthorities);
		} else if (authoritiesConverter.getClass().getName().contains("Mockito")) {
			authBuilder.authorities(Defaults.AUTHORITIES);
		}

		return authBuilder.build();
	}

	protected Map<String, Object> claimsMap(A annotation) {
		return new HashMap<>();
	}

	protected String[] authoritiesOverride(A annotation) {
		return new String[] {};
	}

}
