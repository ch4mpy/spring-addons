package com.c4soft.springaddons.security.test.support.openid;

import java.net.URI;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

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

	ClientRegistrationBuilder scope(String... scopes) {
		delegate.scope(scopes);
		return this;
	}

	ClientRegistrationBuilder scope(Collection<String> scopes) {
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