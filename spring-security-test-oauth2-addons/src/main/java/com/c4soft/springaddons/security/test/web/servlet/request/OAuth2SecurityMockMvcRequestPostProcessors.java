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
package com.c4soft.springaddons.security.test.web.servlet.request;

import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;

import com.c4soft.springaddons.security.oauth2.server.resource.authentication.OAuth2Authentication;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesIntrospectionClaimSet;
import com.c4soft.springaddons.security.oauth2.server.resource.authentication.embedded.WithAuthoritiesJwtClaimSet;
import com.c4soft.springaddons.security.test.support.TestingAuthenticationTokenBuilder;
import com.c4soft.springaddons.security.test.support.introspection.IntrospectionClaimSetAuthenticationTestingBuilder;
import com.c4soft.springaddons.security.test.support.introspection.OAuth2IntrospectionAuthenticationTokenTestingBuilder;
import com.c4soft.springaddons.security.test.support.jwt.JwtAuthenticationTokenTestingBuilder;
import com.c4soft.springaddons.security.test.support.jwt.JwtClaimSetAuthenticationTestingBuilder;
import com.c4soft.springaddons.security.test.support.openid.OAuth2LoginAuthenticationTokenTestingBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public final class OAuth2SecurityMockMvcRequestPostProcessors {

	/**
	 * <p>
	 * Set-up MockMvc security-context with an {@link OAuth2Authentication}&lt;{@link WithAuthoritiesJwtClaimSet}&gt;
	 * </p>
	 *
	 * Sample usage (see show-cases tests for more):
	 * <pre>
	&#64;MockBean
	JwtDecoder jwtDecoder;

	&#64;Autowired
	MockMvc mockMvc;

	&#64;Test
	public void demo() throws Exception {
		mockMvc.perform(get("/restricted/greeting").with(jwtClaimSet(claims -&gt; claims.authorities("AUTHORIZED_PERSONEL"))))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}
	 * </pre>
	 *
	 * @param claimsConsumer configures JWT claim-set
	 * @return JwtClaimSetAuthenticationRequestPostProcessor to further configure
	 */
	public static JwtClaimSetAuthenticationRequestPostProcessor jwtClaimSet(Consumer<WithAuthoritiesJwtClaimSet.Builder<?>> claimsConsumer) {
		return new JwtClaimSetAuthenticationRequestPostProcessor(claimsConsumer);
	}

	/**
	 * <p>
	 * Set-up MockMvc security-context with an {@link OAuth2Authentication}&lt;{@link WithAuthoritiesJwtClaimSet}&gt;
	 * </p>
	 *
	 * Sample usage (see show-cases tests for more):
	 * <pre>
	&#64;MockBean
	JwtDecoder jwtDecoder;

	&#64;Autowired
	MockMvc mockMvc;

	&#64;Test
	public void demo() throws Exception {
		mockMvc.perform(get("/jwt").with(jwtClaimSet()))
			.andExpect(content().string(containsString("Hello, user! You are grantd with [ROLE_USER]")));
	}
	 * </pre>
	 *
	 * @return JwtClaimSetAuthenticationRequestPostProcessor to further configure
	 */
	public static JwtClaimSetAuthenticationRequestPostProcessor jwtClaimSet() {
		return jwtClaimSet(claims -> {}) ;
	}

	/**
	 * <p>
	 * Set-up MockMvc security-context with an {@link OAuth2Authentication}&lt;{@link WithAuthoritiesIntrospectionClaimSet}&gt;
	 * </p>
	 *
	 * Sample usage (see show-cases tests for more):
	 * <pre>
	&#64;Autowired
	MockMvc mockMvc;

	&#64;Test
	public void demo() throws Exception {
		mockMvc.perform(get("/restricted/greeting").with(introspectionClaimSet(claims -&gt; claims.authorities("AUTHORIZED_PERSONEL"))))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}
	 * </pre>
	 *
	 * @param claimsConsumer configures JWT claim-set
	 * @return IntrospectionClaimSetAuthenticationRequestPostProcessor to further configure
	 */
	public static IntrospectionClaimSetAuthenticationRequestPostProcessor introspectionClaimSet(Consumer<WithAuthoritiesIntrospectionClaimSet.Builder<?>> claimsConsumer) {
		return new IntrospectionClaimSetAuthenticationRequestPostProcessor(claimsConsumer);
	}

	/**
	 * <p>
	 * Set-up MockMvc security-context with an {@link OAuth2Authentication}&lt;{@link WithAuthoritiesIntrospectionClaimSet}&gt;
	 * </p>
	 *
	 * Sample usage (see show-cases tests for more):
	 * <pre>
	&#64;Autowired
	MockMvc mockMvc;

	&#64;Test
	public void demo() throws Exception {
		mockMvc.perform(get("/introspection").with(introspectionClaimSet()))
			.andExpect(content().string(containsString("Hello, user! You are grantd with [ROLE_USER]")));
	}
	 * </pre>
	 *
	 * @return IntrospectionClaimSetAuthenticationRequestPostProcessor to further configure
	 */
	public static IntrospectionClaimSetAuthenticationRequestPostProcessor introspectionClaimSet() {
		return introspectionClaimSet(claims -> {}) ;
	}

	/**
	 * <p>
	 * Set-up MockMvc security-context with an {@link JwtAuthenticationToken}
	 * </p>
	 *
	 * Sample usage (see show-cases tests for more):
	 * <pre>
	&#64;MockBean
	JwtDecoder jwtDecoder;

	&#64;Autowired
	MockMvc mockMvc;

	&#64;Test
	public void demo() throws Exception {
		mockMvc.perform(get("/restricted/greeting").with(jwt(new JwtGrantedAuthoritiesConverter()).scopes("AUTHORIZED_PERSONEL")))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}
	 * </pre>
	 *
	 * @param authoritiesConverter converter to extract authorities from the token
	 * @return JwtAuthenticationTokenRequestPostProcessor to further configure
	 */
	public static JwtAuthenticationTokenRequestPostProcessor jwt(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		return new JwtAuthenticationTokenRequestPostProcessor(authoritiesConverter);
	}

	/**
	 * Shortcut for {@code jwt(new JwtGrantedAuthoritiesConverter())}
	 *
	 * @return JwtAuthenticationTokenRequestPostProcessor
	 */
	public static JwtAuthenticationTokenRequestPostProcessor jwt() {
		return jwt(new JwtGrantedAuthoritiesConverter());
	}
	/**
	 * <p>
	 * Set-up MockMvc security-context with an {@link JwtAuthenticationToken}
	 * </p>
	 *
	 * Sample usage (see show-cases tests for more):
	 * <pre>
	&#64;Autowired
	MockMvc mockMvc;

	&#64;Test
	public void demo() throws Exception {
		mockMvc.perform(get("/restricted/greeting").with(introspectedToken().scopes("AUTHORIZED_PERSONEL")))
			.andExpect(content().string(is("Welcome to restricted area.")));
	}
	 * </pre>
	 *
	 * @return OAuth2IntrospectionAuthenticationTokenRequestPostProcessor to further configure
	 */
	public static OAuth2IntrospectionAuthenticationTokenRequestPostProcessor introspectedToken() {
		return new OAuth2IntrospectionAuthenticationTokenRequestPostProcessor();
	}

	public static OAuth2LoginAuthenticationRequestPostProcessor oidcId() {
		return new OAuth2LoginAuthenticationRequestPostProcessor();
	}

	public static TestingAuthenticationRequestPostProcessor testingToken() {
		return new TestingAuthenticationRequestPostProcessor();
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

	public static class JwtAuthenticationTokenRequestPostProcessor extends JwtAuthenticationTokenTestingBuilder<JwtAuthenticationTokenRequestPostProcessor>
			implements
			AuthenticationRequestPostProcessor<JwtAuthenticationToken> {
		public JwtAuthenticationTokenRequestPostProcessor(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
			super(authoritiesConverter);
		}
	}

	public static class OAuth2IntrospectionAuthenticationTokenRequestPostProcessor
			extends
			OAuth2IntrospectionAuthenticationTokenTestingBuilder<OAuth2IntrospectionAuthenticationTokenRequestPostProcessor>
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
