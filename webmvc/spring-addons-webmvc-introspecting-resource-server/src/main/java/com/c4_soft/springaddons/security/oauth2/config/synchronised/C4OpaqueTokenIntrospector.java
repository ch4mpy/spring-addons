package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.Serializable;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2ClaimsConverter;

// FIXME: remove when https://github.com/spring-projects/spring-security/issues/11661 is solved
public class C4OpaqueTokenIntrospector<T extends Map<String, Object> & Serializable> implements OpaqueTokenIntrospector {
	private final NimbusOpaqueTokenIntrospector delegate;
	private final OAuth2ClaimsConverter<T> claimsConverter;
	private final OAuth2AuthoritiesConverter authoritiesConverter;

	public C4OpaqueTokenIntrospector(
			String introspectionUri,
			String clientId,
			String clientSecret,
			OAuth2ClaimsConverter<T> claimsConverter,
			OAuth2AuthoritiesConverter authoritiesConverter) {
		this.delegate = new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
		this.claimsConverter = claimsConverter;
		this.authoritiesConverter = authoritiesConverter;
	}

	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {
		final var auth = this.delegate.introspect(token);
		final var claims = claimsConverter.convert(auth.getAttributes());
		return new OAuthentication<>(claims, authoritiesConverter.convert(claims), token);
	}

}