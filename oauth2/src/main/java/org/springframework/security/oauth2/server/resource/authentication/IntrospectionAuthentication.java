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
import org.springframework.util.StringUtils;

import com.c4soft.oauth2.rfc7662.IntrospectionOAuth2Authorization;
import com.c4soft.oauth2.rfc7662.IntrospectionToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class IntrospectionAuthentication extends AbstractOAuth2Authentication<IntrospectionOAuth2Authorization, IntrospectionToken, String> {
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
		if(StringUtils.hasLength(getAccessToken().getUsername())) {
			return getAccessToken().getUsername();
		}
		return getAccessToken().getSubject();
	}

	public static class Builder {
		private final Converter<IntrospectionToken, Collection<GrantedAuthority>> authoritiesConverter;
		private final IntrospectionOAuth2Authorization.Builder authorizationBuilder;

		public Builder(Converter<IntrospectionToken, Collection<GrantedAuthority>> authoritiesConverter) {
			this.authoritiesConverter = authoritiesConverter;
			this.authorizationBuilder = new IntrospectionOAuth2Authorization.Builder();
		}

		public Builder authorization(Consumer<IntrospectionOAuth2Authorization.Builder> authorizationConsumer) {
			authorizationConsumer.accept(authorizationBuilder);
			return this;
		}

		public IntrospectionAuthentication build() {
			final IntrospectionOAuth2Authorization authorization = authorizationBuilder.build();
			return new IntrospectionAuthentication(authorization, authoritiesConverter.convert(authorization.getAccessToken()));
		}
	}

}
