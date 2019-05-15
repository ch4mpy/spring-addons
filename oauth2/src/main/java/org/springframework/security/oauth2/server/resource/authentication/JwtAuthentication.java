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

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

import com.c4soft.oauth2.rfc7519.Jwt;
import com.c4soft.oauth2.rfc7519.JwtOAuth2Authorization;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class JwtAuthentication extends AbstractOAuth2Authentication<JwtOAuth2Authorization, Jwt, String> {
	private static final long serialVersionUID = -8450928725079141394L;

	/**
	 * @param authorization
	 * @param authorities
	 */
	protected JwtAuthentication(JwtOAuth2Authorization authorization, Collection<GrantedAuthority> authorities) {
		super(authorization, authorities);
	}

	@Override
	public String getName() {
		return getAccessToken().getSubject();
	}

	public static class Builder {
		private final Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;
		private final JwtOAuth2Authorization.Builder authorizationBuilder;

		public Builder(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
			this.authorizationBuilder = new JwtOAuth2Authorization.Builder();
		}

		public Builder authorization(Consumer<JwtOAuth2Authorization.Builder> authorizationConsumer) {
			authorizationConsumer.accept(authorizationBuilder);
			return this;
		}

		public JwtAuthentication build() {
			final JwtOAuth2Authorization authorization = authorizationBuilder.build();
			return new JwtAuthentication(authorization, authoritiesConverter.convert(authorization.getAccessToken()));
		}
	}
}
