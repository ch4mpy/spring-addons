package com.c4soft.springaddons.security.oauth2.server.resource.authentication;

import java.security.Principal;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;

import com.c4soft.oauth2.UnmodifiableClaimSet;

public abstract class AbstractOAuth2ClaimSetAuthenticationManager<T extends UnmodifiableClaimSet & Principal> implements AuthenticationManager {
	private final Converter<T, Collection<GrantedAuthority>> authoritiesConverter;
	private final Set<String> requiredScopes;
	private final Logger logger = LoggerFactory.getLogger(getClass());

	public AbstractOAuth2ClaimSetAuthenticationManager(
			Converter<T, Collection<GrantedAuthority>> authoritiesConverter,
			Set<String> requiredScopes) {
		this.authoritiesConverter = authoritiesConverter;
		this.requiredScopes = requiredScopes;
	}

	protected abstract T extractClaims(BearerTokenAuthenticationToken bearer);

	@Override
	public OAuth2ClaimSetAuthentication<T> authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof BearerTokenAuthenticationToken)) {
			return null;
		}
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

		final T claims = extractClaims(bearer);
		final Set<String> scopes = claims.containsKey("scope") ? claims.getAsStringSet("scope") : claims.getAsStringSet("scp");
		if(scopes == null) {
			logger.info("Token has no scope claim. No filter will beapplied to GrantedAuthority set.");
		}
		checkRequiredScopes(scopes);

		return new OAuth2ClaimSetAuthentication<>(claims, authoritiesConverter);
	}

	private void checkRequiredScopes(final Set<String> scopes) {
		if(requiredScopes != null && !requiredScopes.isEmpty() && (scopes == null || !scopes.containsAll(requiredScopes))) {
			final String msg = String.format("Rejected OAuth2 authentication: %s scopes are required", requiredScopes);
			logger.warn(msg);
			throw new OAuth2AuthenticationException(new BearerTokenError(
					"invalid_token",
					HttpStatus.UNAUTHORIZED,
					msg,
					"",
					scopes.stream().collect(Collectors.joining("[", ", ", "]"))));
		}
	}

}
