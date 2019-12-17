package com.c4_soft.springaddons.security.oauth2.server.resource.authentication;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import com.c4_soft.oauth2.UnmodifiableClaimSet;

public abstract class AbstractClaimSetAuthenticationManager<T extends UnmodifiableClaimSet & Principal> implements AuthenticationManager {
	private final Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter;

	public AbstractClaimSetAuthenticationManager(Converter<Map<String, Object>, Set<GrantedAuthority>> authoritiesConverter) {
		this.authoritiesConverter = authoritiesConverter;
	}

	/**
	 * Retrieves token claims from opaque token (decode a JWT, call introspection end-point, etc.)
	 * @param bearer opaque token
	 * @return token claims
	 */
	protected abstract T extractClaims(BearerTokenAuthenticationToken bearer);

	@Override
	public OAuth2ClaimSetAuthentication<T> authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof BearerTokenAuthenticationToken)) {
			return null;
		}
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

		return new OAuth2ClaimSetAuthentication<>(extractClaims(bearer), authoritiesConverter);
	}

}
