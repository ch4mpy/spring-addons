/*
 * Copyright 2019 Jérôme Wacongne.
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
package org.springframework.security.test.web.servlet.request;

import java.util.Collection;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.test.support.JwtAuthenticationTokenBuilder;
import org.springframework.security.test.support.OAuth2IntrospectionAuthenticationTokenBuilder;
import org.springframework.security.test.support.OAuth2LoginAuthenticationTokenBuilder;
import org.springframework.security.test.support.SimpleTestingAuthenticationTokenBuilder;
import org.springframework.security.test.support.missingpublicapi.AuthenticationRequestPostProcessor;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public final class OAuth2SecurityMockMvcRequestPostProcessors {

	public static AuthenticationRequestPostProcessor authentication(SimpleTestingAuthenticationTokenBuilder auth) {
		return new AuthenticationRequestPostProcessor(auth.build());
	}

	public static AuthenticationRequestPostProcessor authentication() {
		return authentication(new SimpleTestingAuthenticationTokenBuilder());
	}

	public static AuthenticationRequestPostProcessor jwt(JwtAuthenticationToken auth) {
		return new AuthenticationRequestPostProcessor(auth);
	}

	public static AuthenticationRequestPostProcessor jwt(JwtAuthenticationTokenBuilder auth) {
		return new AuthenticationRequestPostProcessor(auth.build());
	}

	public static AuthenticationRequestPostProcessor jwt(Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {
		return new AuthenticationRequestPostProcessor(
				new JwtAuthenticationTokenBuilder(authoritiesConverter)
				.build());
	}

	/**
	 * Establish a {@link SecurityContext} that has an
	 * {@link OAuth2IntrospectionAuthenticationToken} for the
	 * {@link Authentication} and an {@link OAuth2AccessToken} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the OAuth2AccessToken value to be valid.
	 *
	 * <p>
	 * The support works by associating the authentication to the HttpServletRequest. To associate
	 * the request to the SecurityContextHolder you need to ensure that the
	 * SecurityContextPersistenceFilter is associated with the MockMvc instance. A few
	 * ways to do this are:
	 * </p>
	 *
	 * <ul>
	 * <li>Invoking apply {@link SecurityMockMvcConfigurers#springSecurity()}</li>
	 * <li>Adding Spring Security's FilterChainProxy to MockMvc</li>
	 * <li>Manually adding {@link SecurityContextPersistenceFilter} to the MockMvc
	 * instance may make sense when using MockMvcBuilders standaloneSetup</li>
	 * </ul>
	 *
	 * @return the {@link AccessTokenRequestPostProcessor} for additional customization
	 */
	public static AuthenticationRequestPostProcessor accessToken(OAuth2IntrospectionAuthenticationToken authentication) {
		return new AuthenticationRequestPostProcessor(authentication);
	}

	public static AuthenticationRequestPostProcessor accessToken(OAuth2IntrospectionAuthenticationTokenBuilder authentication) {
		return accessToken(authentication.build());
	}

	/**
	 * @deprecated this is a draft not ready for use: I don't know enough about OpenID spec and have not understood enough of Spring impl to provide anything reliable yet
	 */
	@Deprecated
	public static AuthenticationRequestPostProcessor oidcId(OAuth2LoginAuthenticationToken authorization) {
		return new AuthenticationRequestPostProcessor(authorization);
	}

	/**
	 * @deprecated this is a draft not ready for use: I don't know enough about OpenID spec and have not understood enough of Spring impl to provide anything reliable yet
	 */
	@Deprecated
	public static AuthenticationRequestPostProcessor oidcId(OAuth2LoginAuthenticationTokenBuilder authorization) {
		return oidcId(authorization.build());
	}
}
