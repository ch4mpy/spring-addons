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

import java.time.Instant;
import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import com.c4soft.oauth2.rfc7662.IntrospectionClaimSet;
import com.c4soft.oauth2.rfc7662.IntrospectionOAuth2Authorization;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class IntrospectionAuthentication extends AbstractOAuth2Authentication<IntrospectionOAuth2Authorization, IntrospectionClaimSet, String> {
	private static final long serialVersionUID = -5121824981488824261L;

	/**
	 * @param authorization
	 * @param authorities
	 */
	protected IntrospectionAuthentication(IntrospectionOAuth2Authorization authorization, Collection<GrantedAuthority> authorities) {
		super(authorization, authorities);
	}

	@Override
	public String getName() {
		if (StringUtils.hasLength(getAccessToken().getUsername())) {
			return getAccessToken().getUsername();
		}
		return getAccessToken().getSubject();
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private Converter<IntrospectionOAuth2Authorization, Collection<GrantedAuthority>> authoritiesConverter;
		private IntrospectionOAuth2Authorization.Builder<?> authorizationBuilder;

		public Builder() {
			this.authoritiesConverter = claims -> claims.getScope().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
			this.authorizationBuilder = IntrospectionOAuth2Authorization.builder();
		}

		public Builder authoritiesConverter(Converter<IntrospectionOAuth2Authorization, Collection<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
			return this;
		}

		public Builder authorizationBuilder(IntrospectionOAuth2Authorization.Builder<?> authorizationBuilder) {
			this.authorizationBuilder = authorizationBuilder;
			return this;
		}

		public Builder accessToken(IntrospectionClaimSet introspectionClaims) {
			this.authorizationBuilder.accessToken(introspectionClaims);
			return this;
		}

		public Builder expiresAt(Instant expiresAt) {
			this.authorizationBuilder.expiresAt(expiresAt);
			return this;
		}

		public Builder expiresIn(Long seconds) {
			this.authorizationBuilder.expiresIn(seconds);
			return this;
		}

		public Builder refreshToken(String refreshToken) {
			this.authorizationBuilder.refreshToken(refreshToken);
			return this;
		}

		public Builder scope(String scope) {
			this.authorizationBuilder.scope(scope);
			return this;
		}

		public Builder scopes(String... scopes) {
			this.authorizationBuilder.scopes(scopes);
			return this;
		}

		public IntrospectionAuthentication build() {
			final IntrospectionOAuth2Authorization authorization = authorizationBuilder.build();
			return new IntrospectionAuthentication(authorization, authoritiesConverter.convert(authorization));
		}
	}

}
