package com.c4soft.springaddons.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Map;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOAuth2TokenIntrospectionClient;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2TokenIntrospectionClient;
import org.springframework.util.StringUtils;

import com.c4soft.oauth2.rfc7662.IntrospectionClaimSet;

public class OAuth2ClaimSetIntrospectionAuthenticationManager<T extends IntrospectionClaimSet> implements AuthenticationManager {
	private final OAuth2TokenIntrospectionClient introspectionClient;
	private final Converter<Map<String, Object>, T> claimsConverter;
	private final Converter<T, Collection<GrantedAuthority>> authoritiesConverter;

	public OAuth2ClaimSetIntrospectionAuthenticationManager(
			String introspectionEdpoint,
			String introspectionUsername,
			String introspectionPassword,
			Converter<Map<String, Object>, T> claimsConverter,
			Converter<T, Collection<GrantedAuthority>> authoritiesConverter) {
		this.introspectionClient = new NimbusOAuth2TokenIntrospectionClient(
				introspectionEdpoint,
				introspectionUsername,
				introspectionPassword);
		this.claimsConverter = claimsConverter;
		this.authoritiesConverter = authoritiesConverter;
	}

	@Override
	public OAuth2ClaimSetAuthentication<T> authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof BearerTokenAuthenticationToken)) {
			return null;
		}
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

		try {
			final Map<String, Object> claims = introspectionClient.introspect(bearer.getToken());
			return new OAuth2ClaimSetAuthentication<>(claimsConverter.convert(claims), authoritiesConverter);
		} catch (OAuth2IntrospectionException failed) {
			OAuth2Error invalidToken = invalidToken(failed.getMessage());
			throw new OAuth2AuthenticationException(invalidToken);
		}
	}

	private static BearerTokenError invalidToken(String message) {
		final String msg = StringUtils.hasLength(message) ? message
				: "An error occurred while attempting to introspect the token: Invalid token";

		return new BearerTokenError("invalid_token", HttpStatus.UNAUTHORIZED, msg,
				"https://tools.ietf.org/html/rfc7662#section-2.2");
	}

}
