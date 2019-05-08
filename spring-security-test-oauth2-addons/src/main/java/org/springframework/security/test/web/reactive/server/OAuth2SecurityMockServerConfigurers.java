/*
 * Copyright 2019 Jérôme Wacongne.
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
package org.springframework.security.test.web.reactive.server;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.test.support.AuthenticationBuilder;
import org.springframework.security.test.support.introspection.OAuth2IntrospectionAuthenticationTokenTestingBuilder;
import org.springframework.security.test.support.jwt.JwtAuthenticationTokenTestingBuilder;
import org.springframework.security.test.support.openid.OAuth2LoginAuthenticationTokenTestingBuilder;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2SecurityMockServerConfigurers {
	public static <T extends WebTestClientConfigurer & MockServerConfigurer, U extends Authentication> T
			mockAuthentication(AuthenticationBuilder<U> authentication) {
		return org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication(authentication.build());
	}

	public static JwtAuthenticationTokenConfigurer mockJwt(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		return new JwtAuthenticationTokenConfigurer(authoritiesConverter);
	}

	public static OAuth2IntrospectionAuthenticationTokenConfigurer mockAccessToken() {
		return new OAuth2IntrospectionAuthenticationTokenConfigurer();
	}

	public static OAuth2LoginAuthenticationTokenConfigurer mockOidcId(AuthorizationGrantType requestAuthorizationGrantType) {
		return new OAuth2LoginAuthenticationTokenConfigurer(requestAuthorizationGrantType);
	}

	public static OAuth2LoginAuthenticationTokenConfigurer mockOidcId() {
		return new OAuth2LoginAuthenticationTokenConfigurer();
	}

	public static class JwtAuthenticationTokenConfigurer extends JwtAuthenticationTokenTestingBuilder<JwtAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<JwtAuthenticationToken> {

		public JwtAuthenticationTokenConfigurer(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			super(authoritiesConverter);
		}
	}

	public static class OAuth2IntrospectionAuthenticationTokenConfigurer extends OAuth2IntrospectionAuthenticationTokenTestingBuilder<OAuth2IntrospectionAuthenticationTokenConfigurer> implements AuthenticationConfigurer<OAuth2IntrospectionAuthenticationToken> {
	}

	public static class OAuth2LoginAuthenticationTokenConfigurer extends OAuth2LoginAuthenticationTokenTestingBuilder<OAuth2LoginAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<OAuth2LoginAuthenticationToken> {

		public OAuth2LoginAuthenticationTokenConfigurer(AuthorizationGrantType requestAuthorizationGrantType) {
			super(requestAuthorizationGrantType);
		}

		public OAuth2LoginAuthenticationTokenConfigurer() {
			super();
		}
	}
}
