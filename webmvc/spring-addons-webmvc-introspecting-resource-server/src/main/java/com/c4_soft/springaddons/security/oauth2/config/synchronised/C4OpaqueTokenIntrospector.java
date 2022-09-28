package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Collection;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

public class C4OpaqueTokenIntrospector implements OpaqueTokenIntrospector {
	private final NimbusOpaqueTokenIntrospector delegate;
	private final Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter;

	public C4OpaqueTokenIntrospector(
			String introspectionUri,
			String clientId,
			String clientSecret,
			Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
		this.delegate = new NimbusOpaqueTokenIntrospector(introspectionUri, clientId, clientSecret);
		this.authoritiesConverter = authoritiesConverter;
	}

	@SuppressWarnings("unchecked")
	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {
		final OAuth2AuthenticatedPrincipal auth = this.delegate.introspect(token);
		final Collection<? extends GrantedAuthority> authorities = authoritiesConverter.convert(auth.getAttributes());
		return new OAuth2IntrospectionAuthenticatedPrincipal(auth.getAttributes(), (Collection<GrantedAuthority>) authorities);
	}

}