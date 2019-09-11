package com.c4_soft.springaddons.security.oauth2.server.resource.authentication;

import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import com.c4_soft.oauth2.rfc7662.IntrospectionClaimSet;

public class IntrospectionClaimSetAuthenticationManager<T extends IntrospectionClaimSet> extends AbstractClaimSetAuthenticationManager<T> {
	private final OpaqueTokenIntrospector introspectionClient;
	private final Converter<Map<String, Object>, T> typedClaimsExtractor;

	/**
	 * Regarding {@code typedClaimsExtractor}, a simple reference to a constructor (like {@code IntrospectionClaimSet::new}) or
	 * factory method (like {@code WithAuthoritiesIntrospectionClaimSet.builder("authorities")::build}
	 * should be enough
	 * @param introspectionEdpoint URI for introspection end-point
	 * @param introspectionUsername introspection client name
	 * @param introspectionPassword introspection client password
	 * @param typedClaimsExtractor casts {@code Map<String, Object>} into {@code JwtClaimSet} implementation
	 * @param authoritiesConverter retrieves authorities set from token claims
	 */
	public IntrospectionClaimSetAuthenticationManager(
			String introspectionEdpoint,
			String introspectionUsername,
			String introspectionPassword,
			Converter<Map<String, Object>, T> typedClaimsExtractor,
			Converter<T, Set<GrantedAuthority>> authoritiesConverter) {
		super(authoritiesConverter);
		this.introspectionClient = new NimbusOpaqueTokenIntrospector(
				introspectionEdpoint,
				introspectionUsername,
				introspectionPassword);
		this.typedClaimsExtractor = typedClaimsExtractor;
	}

	@Override
	protected T extractClaims(BearerTokenAuthenticationToken bearer) {
		final OAuth2AuthenticatedPrincipal principal = introspectionClient.introspect(bearer.getToken());
		return typedClaimsExtractor.convert(principal.getAttributes());
	}

}
