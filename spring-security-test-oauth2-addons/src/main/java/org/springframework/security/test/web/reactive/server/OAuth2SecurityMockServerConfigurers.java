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
package org.springframework.security.test.web.reactive.server;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionAuthenticationToken;
import org.springframework.security.test.support.JwtAuthenticationTokenBuilder;
import org.springframework.security.test.support.OAuth2IntrospectionAuthenticationTokenBuilder;
import org.springframework.security.test.support.OAuth2LoginAuthenticationTokenBuilder;
import org.springframework.security.test.support.SimpleTestingAuthenticationTokenBuilder;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;

/**
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class OAuth2SecurityMockServerConfigurers {

	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockAuthentication(TestingAuthenticationToken authentication) {
		return org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication(authentication);
	}

	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockAuthentication(SimpleTestingAuthenticationTokenBuilder authentication) {
		return mockAuthentication(authentication.build());
	}

	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockJwt(JwtAuthenticationToken authentication) {
		return org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication(authentication);
	}

	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockJwt(JwtAuthenticationTokenBuilder authentication) {
		return mockJwt(authentication.build());
	}

	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockAccessToken(OAuth2IntrospectionAuthenticationToken authentication) {
		return org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication(authentication);
	}

	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockAccessToken(OAuth2IntrospectionAuthenticationTokenBuilder authentication) {
		return mockAccessToken(authentication.build());
	}

	/**
	 * @deprecated this is a draft not ready for use: I don't know enough about OpenID spec and have not understood enough of Spring impl to provide anything reliable yet
	 */
	@Deprecated
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockOidcId(OAuth2LoginAuthenticationToken authentication) {
		return org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockAuthentication(authentication);
	}
	/**
	 * @deprecated this is a draft not ready for use: I don't know enough about OpenID spec and have not understood enough of Spring impl to provide anything reliable yet
	 */
	@Deprecated
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockOidcId(OAuth2LoginAuthenticationTokenBuilder authentication) {
		return mockOidcId(authentication.build());
	}
}
