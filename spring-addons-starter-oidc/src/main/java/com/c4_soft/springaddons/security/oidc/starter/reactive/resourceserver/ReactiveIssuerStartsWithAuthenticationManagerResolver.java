package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.web.bind.annotation.ResponseStatus;

import reactor.core.publisher.Mono;

/**
 * Dynamic multi-tenancy based on issuer prefix (for instance, trust all reams from a given Keycloak Server)
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
public class ReactiveIssuerStartsWithAuthenticationManagerResolver implements ReactiveAuthenticationManagerResolver<String> {

	private final String issuerPrefix;
	private final Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> authenticationConverter;
	private final Map<String, ReactiveAuthenticationManager> jwtManagers = new ConcurrentHashMap<>();

	/**
	 * @param issuerPrefix            what access tokens iss claim must start with
	 * @param authenticationConverter converter from a valid {@link Jwt} to an {@link AbstractAuthenticationToken} instance
	 */
	public ReactiveIssuerStartsWithAuthenticationManagerResolver(
			String issuerPrefix,
			Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> authenticationConverter) {
		super();
		this.issuerPrefix = issuerPrefix.toString();
		this.authenticationConverter = authenticationConverter;
	}

	@Override
	public Mono<ReactiveAuthenticationManager> resolve(String issuer) {
		if (!jwtManagers.containsKey(issuer)) {
			if (!issuer.startsWith(issuerPrefix)) {
				throw new UnknownIssuerException(issuer);
			}
			final var decoder = NimbusReactiveJwtDecoder.withIssuerLocation(issuer).build();
			var provider = new JwtReactiveAuthenticationManager(decoder);
			provider.setJwtAuthenticationConverter(authenticationConverter);
			jwtManagers.put(issuer, provider::authenticate);
		}
		return Mono.just(jwtManagers.get(issuer));

	}

	@ResponseStatus(HttpStatus.UNAUTHORIZED)
	static class UnknownIssuerException extends RuntimeException {
		private static final long serialVersionUID = 4177339081914400888L;

		public UnknownIssuerException(String issuer) {
			super("Unknown issuer: %s".formatted(issuer));
		}
	}
}
