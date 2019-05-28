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
package org.springframework.security.test.web.servlet.request;

import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
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
public final class OAuth2SecurityMockMvcRequestPostProcessors {

	public static JwtClaimSetAuthenticationRequestPostProcessor jwtClaimSet(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
		return new JwtClaimSetAuthenticationRequestPostProcessor(claimsConsumer);
	}

	public static JwtClaimSetAuthenticationRequestPostProcessor jwtClaimSet() {
		return jwtClaimSet(claims -> {}) ;
	}

	public static IntrospectionClaimSetAuthenticationRequestPostProcessor introspectionClaimSet(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
		return new IntrospectionClaimSetAuthenticationRequestPostProcessor(claimsConsumer);
	}

	public static IntrospectionClaimSetAuthenticationRequestPostProcessor introspectionClaimSet() {
		return introspectionClaimSet(claims -> {}) ;
	}

	public static JwtAuthenticationRequestPostProcessor jwt(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		return new JwtAuthenticationRequestPostProcessor(authoritiesConverter);
	}

	public static OAuth2IntrospectionAuthenticationRequestPostProcessor accessToken() {
		return new OAuth2IntrospectionAuthenticationRequestPostProcessor();
	}

	public static OAuth2LoginAuthenticationRequestPostProcessor oidcId() {
		return new OAuth2LoginAuthenticationRequestPostProcessor();
	}

	public static TestingAuthenticationRequestPostProcessor testingToken() {
		return new TestingAuthenticationRequestPostProcessor();
	}

	public static class JwtAuthenticationRequestPostProcessor extends JwtAuthenticationTokenTestingBuilder<JwtAuthenticationRequestPostProcessor>
			implements
			AuthenticationRequestPostProcessor<JwtAuthenticationToken> {
		public JwtAuthenticationRequestPostProcessor(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			super(authoritiesConverter);
		}
	}

	public static class JwtClaimSetAuthenticationRequestPostProcessor extends JwtClaimSetAuthenticationTestingBuilder
			implements AuthenticationRequestPostProcessor<OAuth2Authentication<WithAuthoritiesJwtClaimSet>> {
		public JwtClaimSetAuthenticationRequestPostProcessor(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
			super(claimsConsumer);
		}
	}

	public static class IntrospectionClaimSetAuthenticationRequestPostProcessor extends IntrospectionClaimSetAuthenticationTestingBuilder
			implements AuthenticationRequestPostProcessor<OAuth2Authentication<WithAuthoritiesIntrospectionClaimSet>> {
		public IntrospectionClaimSetAuthenticationRequestPostProcessor(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
			super(claimsConsumer);
		}
	}

	public static class OAuth2IntrospectionAuthenticationRequestPostProcessor
			extends
			OAuth2IntrospectionAuthenticationTokenTestingBuilder<OAuth2IntrospectionAuthenticationRequestPostProcessor>
			implements
			AuthenticationRequestPostProcessor<OAuth2IntrospectionAuthenticationToken> {
	}

	public static class OAuth2LoginAuthenticationRequestPostProcessor
			extends
			OAuth2LoginAuthenticationTokenTestingBuilder<OAuth2LoginAuthenticationRequestPostProcessor>
			implements
			AuthenticationRequestPostProcessor<OAuth2LoginAuthenticationToken> {
	}

	public static class TestingAuthenticationRequestPostProcessor
			extends
			TestingAuthenticationTokenBuilder<TestingAuthenticationRequestPostProcessor>
			implements
			AuthenticationRequestPostProcessor<TestingAuthenticationToken> {
	}
}
