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
package com.c4soft.springaddons.security.test.support.missingpublicapi;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import com.c4soft.oauth2.ModifiableClaimSet;

/**
 * Builder for {@link OAuth2AuthorizationRequest}
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class AuthorizationRequestBuilder {
	private final OAuth2AuthorizationRequest.Builder delegate;
	private final ModifiableClaimSet additionalParameters;

	public AuthorizationRequestBuilder(final AuthorizationGrantType authorizationGrantType) {
		this.additionalParameters = new ModifiableClaimSet();
		this.delegate = authorizationRequestBuilder(authorizationGrantType)
				.additionalParameters(this.additionalParameters)
				.attributes(new HashMap<>());
	}

	public AuthorizationRequestBuilder additionalParameter(String name, Object value) {
		additionalParameters.put(name, value);
		return this;
	}

	public AuthorizationRequestBuilder requestUri(URI authorizationRequestUri) {
		delegate.authorizationRequestUri(authorizationRequestUri.toString());
		return this;
	}

	public AuthorizationRequestBuilder authorizationUri(URI authorizationUri) {
		delegate.authorizationUri(authorizationUri.toString());
		return this;
	}

	public AuthorizationRequestBuilder clientId(String clientId) {
		delegate.clientId(clientId);
		return this;
	}

	public AuthorizationRequestBuilder redirectUri(URI redirectUri) {
		delegate.redirectUri(redirectUri.toString());
		return this;
	}

	public AuthorizationRequestBuilder state(String state) {
		delegate.state(state);
		return this;
	}

	public AuthorizationRequestBuilder scopes(String... scopes) {
		delegate.scope(scopes);
		return this;
	}

	public AuthorizationRequestBuilder scopes(Set<String> scopes) {
		delegate.scopes(scopes);
		return this;
	}

	public OAuth2AuthorizationRequest build(Map<String, Object> attributes) {
		return delegate.attributes(attributes).build();
	}

	private static OAuth2AuthorizationRequest.Builder authorizationRequestBuilder(AuthorizationGrantType authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
			return OAuth2AuthorizationRequest.authorizationCode();
		}
		if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
			return OAuth2AuthorizationRequest.implicit();
		}
		throw new UnsupportedOperationException(
				"Only authorization_code and implicit grant types are supported for MockOAuth2AuthorizationRequest");
	}
}