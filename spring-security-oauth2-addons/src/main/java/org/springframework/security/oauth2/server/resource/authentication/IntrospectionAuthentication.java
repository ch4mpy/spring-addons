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
package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import com.c4soft.oauth2.rfc7662.IntrospectionClaimSet;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class IntrospectionAuthentication extends AbstractOAuth2Authentication<IntrospectionClaimSet> {
	private static final long serialVersionUID = -5121824981488824261L;

	/**
	 * @param claims
	 * @param authorities
	 */
	protected IntrospectionAuthentication(IntrospectionClaimSet claims, Collection<GrantedAuthority> authorities) {
		super(claims, authorities);
	}

	@Override
	public String getName() {
		if (StringUtils.hasLength(getClaims().getUsername())) {
			return getClaims().getUsername();
		}
		return getClaims().getSubject();
	}

	@SuppressWarnings("unchecked")
	public static <T extends SpringIntrospectionClaimSet.Builder<T>> Builder<T> builder() {
		return new Builder<>((SpringIntrospectionClaimSet.Builder<T>) SpringIntrospectionClaimSet.builder());
	}

	public static class Builder<T extends SpringIntrospectionClaimSet.Builder<T>> {
		private Converter<SpringIntrospectionClaimSet, Collection<GrantedAuthority>> authoritiesConverter;
		private final SpringIntrospectionClaimSet.Builder<T> claimsBuilder;

		public Builder(SpringIntrospectionClaimSet.Builder<T> claimsBuilder) {
			this.authoritiesConverter = claims -> claims.getAuthorities().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
			this.claimsBuilder = claimsBuilder;
		}

		public Builder<T> authoritiesConverter(Converter<SpringIntrospectionClaimSet, Collection<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
			return this;
		}

		public Builder<T> claimSet(Consumer<SpringIntrospectionClaimSet.Builder<T>> claimsBuilderConsumer) {
			claimsBuilderConsumer.accept(claimsBuilder);
			return this;
		}

		public IntrospectionAuthentication build() {
			final SpringIntrospectionClaimSet authorization = claimsBuilder.build();
			return new IntrospectionAuthentication(authorization, authoritiesConverter.convert(authorization));
		}
	}

}
