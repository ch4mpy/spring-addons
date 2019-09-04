package com.c4_soft.springaddons.security.oauth2.server.resource.authentication;

import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import com.c4_soft.oauth2.rfc7519.JwtClaimSet;

public class JwtClaimSetAuthenticationManager<T extends JwtClaimSet> extends AbstractClaimSetAuthenticationManager<T> {
	private final JwtDecoder jwtDecoder;
	private final Converter<Map<String, Object>, T> typedClaimsExtractor;

	/**
	 * Regarding {@code typedClaimsExtractor}, a simple reference to a constructor (like {@code JwtClaimSet::new}) or
	 * factory method (like {@code WithAuthoritiesJwtClaimSet.builder("authorities")::build}
	 * should be enough
	 * @param jwtDecoder regular Spring application JWT decoder
	 * @param typedClaimsExtractor casts {@code Map<String, Object>} into {@code JwtClaimSet} implementation
	 * @param authoritiesConverter retrieves authorities set from token claims
	 */
	public JwtClaimSetAuthenticationManager(
			JwtDecoder jwtDecoder,
			Converter<Map<String, Object>, T> typedClaimsExtractor,
			Converter<T, Set<GrantedAuthority>> authoritiesConverter) {
		super(authoritiesConverter);
		this.jwtDecoder = jwtDecoder;
		this.typedClaimsExtractor = typedClaimsExtractor;
	}

	@Override
	protected T extractClaims(BearerTokenAuthenticationToken bearer) {
		final Jwt jwt = jwtDecoder.decode(bearer.getToken());
		return typedClaimsExtractor.convert(jwt.getClaims());
	}

}
