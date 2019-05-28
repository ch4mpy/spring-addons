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
import java.util.Collection;
import java.util.Map;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Builder for {@link ClientRegistration}
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class ClientRegistrationBuilder {
	private final ClientRegistration.Builder delegate;

	public ClientRegistrationBuilder(String registrationId) {
		this.delegate = ClientRegistration.withRegistrationId(registrationId);
	}

	public ClientRegistrationBuilder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
		delegate.authorizationGrantType(authorizationGrantType);
		return this;
	}

	public ClientRegistrationBuilder authorizationUri(URI authorizationUri) {
		delegate.authorizationUri(authorizationUri.toString());
		return this;
	}

	public ClientRegistrationBuilder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
		delegate.clientAuthenticationMethod(clientAuthenticationMethod);
		return this;
	}

	public ClientRegistrationBuilder clientId(String clientId) {
		delegate.clientId(clientId);
		return this;
	}

	public ClientRegistrationBuilder clientName(String clientName) {
		delegate.clientName(clientName);
		return this;
	}

	public ClientRegistrationBuilder clientSecret(String clientSecret) {
		delegate.clientSecret(clientSecret);
		return this;
	}

	public ClientRegistrationBuilder jwkSetUri(URI jwkSetUri) {
		delegate.jwkSetUri(jwkSetUri.toString());
		return this;
	}

	public ClientRegistrationBuilder providerConfigurationMetadata(Map<String, Object> configurationMetadata) {
		delegate.providerConfigurationMetadata(configurationMetadata);
		return this;
	}

	public ClientRegistrationBuilder redirectUriTemplate(String redirectUriTemplate) {
		delegate.redirectUriTemplate(redirectUriTemplate);
		return this;
	}

	public ClientRegistrationBuilder registrationId(String registrationId) {
		delegate.registrationId(registrationId);
		return this;
	}

	public ClientRegistrationBuilder scope(String... scopes) {
		delegate.scope(scopes);
		return this;
	}

	public ClientRegistrationBuilder scope(Collection<String> scopes) {
		delegate.scope(scopes);
		return this;
	}

	public ClientRegistrationBuilder tokenUri(URI tokenUri) {
		delegate.tokenUri(tokenUri.toString());
		return this;
	}

	public ClientRegistrationBuilder userInfoAuthenticationMethod(AuthenticationMethod userInfoAuthenticationMethod) {
		delegate.userInfoAuthenticationMethod(userInfoAuthenticationMethod);
		return this;
	}

	public ClientRegistrationBuilder userInfoUri(URI userInfoUri) {
		delegate.userInfoUri(userInfoUri.toString());
		return this;
	}

	public ClientRegistrationBuilder userNameAttributeName(String nameAttributeName) {
		delegate.userNameAttributeName(nameAttributeName);
		return this;
	}

	public ClientRegistration build() {
		return delegate.build();
	}
}