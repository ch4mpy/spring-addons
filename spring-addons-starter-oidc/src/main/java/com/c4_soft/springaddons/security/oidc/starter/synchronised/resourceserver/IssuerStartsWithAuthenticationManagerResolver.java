package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Dynamic multi-tenancy based on issuer prefix (for instance, trust all reams from a given Keycloak Server)
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class IssuerStartsWithAuthenticationManagerResolver implements AuthenticationManagerResolver<String> {

	private final String issuerPrefix;
	private final Converter<Jwt, AbstractAuthenticationToken> authenticationConverter;
	private final Map<String, AuthenticationManager> jwtManagers = new ConcurrentHashMap<>();

	/**
	 * @param issuerPrefix            what access tokens iss claim must start with
	 * @param authenticationConverter converter from a valid {@link Jwt} to an {@link AbstractAuthenticationToken} instance
	 */
	public IssuerStartsWithAuthenticationManagerResolver(String issuerPrefix, Converter<Jwt, AbstractAuthenticationToken> authenticationConverter) {
		super();
		this.issuerPrefix = issuerPrefix.toString();
		this.authenticationConverter = authenticationConverter;
	}

	@Override
	public AuthenticationManager resolve(String issuer) {
		if (!jwtManagers.containsKey(issuer)) {
			if (!issuer.startsWith(issuerPrefix)) {
				throw new UnknownIssuerException(issuer);
			}
			final var decoder = NimbusJwtDecoder.withIssuerLocation(issuer).build();
			var provider = new JwtAuthenticationProvider(decoder);
			provider.setJwtAuthenticationConverter(authenticationConverter);
			jwtManagers.put(issuer, provider::authenticate);
		}
		return jwtManagers.get(issuer);

	}

	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	static class UnknownIssuerException extends RuntimeException {
		private static final long serialVersionUID = -7140122776788781704L;

		public UnknownIssuerException(String issuer) {
			super("Unknown issuer: %s".formatted(issuer));
		}
	}
}
