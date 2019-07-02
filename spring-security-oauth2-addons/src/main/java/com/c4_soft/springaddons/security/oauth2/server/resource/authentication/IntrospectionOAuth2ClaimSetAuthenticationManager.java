package com.c4_soft.springaddons.security.oauth2.server.resource.authentication;

import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOAuth2TokenIntrospectionClient;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2TokenIntrospectionClient;

import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;

public class IntrospectionOAuth2ClaimSetAuthenticationManager<T extends IntrospectionClaimSet> extends AbstractOAuth2ClaimSetAuthenticationManager<T> {
	private final OAuth2TokenIntrospectionClient introspectionClient;
	private final Converter<Map<String, Object>, T> claimsConverter;

	public IntrospectionOAuth2ClaimSetAuthenticationManager(
			String introspectionEdpoint,
			String introspectionUsername,
			String introspectionPassword,
			Converter<Map<String, Object>, T> claimsConverter,
			Converter<T, Set<GrantedAuthority>> authoritiesConverter,
			Set<String> requiredScopes) {
		super(authoritiesConverter, requiredScopes);
		this.introspectionClient = new NimbusOAuth2TokenIntrospectionClient(
				introspectionEdpoint,
				introspectionUsername,
				introspectionPassword);
		this.claimsConverter = claimsConverter;
	}

	@Override
	protected T extractClaims(BearerTokenAuthenticationToken bearer) {
		final Map<String, Object> introspectedClaims = introspectionClient.introspect(bearer.getToken());
		return claimsConverter.convert(introspectedClaims);
	}

}
