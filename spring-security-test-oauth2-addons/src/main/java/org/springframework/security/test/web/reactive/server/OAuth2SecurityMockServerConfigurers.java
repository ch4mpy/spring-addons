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
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2Authentication;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import org.springframework.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;
import org.springframework.security.test.support.TestingAuthenticationTokenBuilder;
import org.springframework.security.test.support.introspection.IntrospectionClaimSetAuthenticationTestingBuilder;
import org.springframework.security.test.support.introspection.OAuth2IntrospectionAuthenticationTokenTestingBuilder;
import org.springframework.security.test.support.jwt.JwtAuthenticationTokenTestingBuilder;
import org.springframework.security.test.support.jwt.JwtClaimSetAuthenticationTestingBuilder;
import org.springframework.security.test.support.openid.OAuth2LoginAuthenticationTokenTestingBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2SecurityMockServerConfigurers {

	public static JwtClaimSetAuthenticationConfigurer mockJwtClaimSet(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
		return new JwtClaimSetAuthenticationConfigurer(claimsConsumer);
	}

	public static JwtClaimSetAuthenticationConfigurer mockJwtClaimSet() {
		return new JwtClaimSetAuthenticationConfigurer(claims -> {});
	}

	public static IntrospectionClaimSetAuthenticationConfigurer mockIntrospectionClaimSet(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
		return new IntrospectionClaimSetAuthenticationConfigurer(claimsConsumer);
	}

	public static IntrospectionClaimSetAuthenticationConfigurer mockIntrospectionClaimSet() {
		return new IntrospectionClaimSetAuthenticationConfigurer(claims -> {});
	}

	/**
	 * @param authoritiesConverter Spring default one is {@link JwtGrantedAuthoritiesConverter}
	 * @return WebTestClient configurer (mutator) to further configure
	 */
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

	public static TestingAuthenticationTokenConfigurer mockTestingToken() {
		return new TestingAuthenticationTokenConfigurer();
	}


	public static class JwtAuthenticationTokenConfigurer extends JwtAuthenticationTokenTestingBuilder<JwtAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<JwtAuthenticationToken> {

		public JwtAuthenticationTokenConfigurer(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			super(authoritiesConverter);
		}
	}

	public static class JwtClaimSetAuthenticationConfigurer extends JwtClaimSetAuthenticationTestingBuilder
			implements AuthenticationConfigurer<OAuth2Authentication<WithAuthoritiesJwtClaimSet>> {
		public JwtClaimSetAuthenticationConfigurer(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
			super(claimsConsumer);
		}
	}

	public static class IntrospectionClaimSetAuthenticationConfigurer extends IntrospectionClaimSetAuthenticationTestingBuilder
			implements AuthenticationConfigurer<OAuth2Authentication<WithAuthoritiesIntrospectionClaimSet>> {
		public IntrospectionClaimSetAuthenticationConfigurer(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
			super(claimsConsumer);
		}
	}

	public static class OAuth2IntrospectionAuthenticationTokenConfigurer
			extends
			OAuth2IntrospectionAuthenticationTokenTestingBuilder<OAuth2IntrospectionAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<OAuth2IntrospectionAuthenticationToken> {
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

	public static class TestingAuthenticationTokenConfigurer extends TestingAuthenticationTokenBuilder<TestingAuthenticationTokenConfigurer>
			implements
			AuthenticationConfigurer<TestingAuthenticationToken> {
	}
}
