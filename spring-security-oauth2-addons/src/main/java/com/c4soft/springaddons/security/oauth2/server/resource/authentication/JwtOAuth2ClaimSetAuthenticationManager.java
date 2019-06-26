package com.c4soft.springaddons.security.oauth2.server.resource.authentication;

import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import com.c4soft.oauth2.rfc7519.JwtClaimSet;

public class JwtOAuth2ClaimSetAuthenticationManager<T extends JwtClaimSet> extends AbstractOAuth2ClaimSetAuthenticationManager<T> {
	private final JwtDecoder jwtDecoder;
	private final Converter<Map<String, Object>, T> claimsConverter;

	public JwtOAuth2ClaimSetAuthenticationManager(
			JwtDecoder jwtDecoder,
			Converter<Map<String, Object>, T> claimsConverter,
			Converter<T, Set<GrantedAuthority>> authoritiesConverter,
			Set<String> requiredScopes) {
		super(authoritiesConverter, requiredScopes);
		this.jwtDecoder = jwtDecoder;
		this.claimsConverter = claimsConverter;
	}

	@Override
	protected T extractClaims(BearerTokenAuthenticationToken bearer) {
		final Jwt jwt = jwtDecoder.decode(bearer.getToken());
		return claimsConverter.convert(jwt.getClaims());
	}

}
