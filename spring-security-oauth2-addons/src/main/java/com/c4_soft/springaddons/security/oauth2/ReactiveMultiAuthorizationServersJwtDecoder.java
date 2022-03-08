package com.c4_soft.springaddons.security.oauth2;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;

import com.fasterxml.jackson.databind.ObjectMapper;

import reactor.core.publisher.Mono;

public class ReactiveMultiAuthorizationServersJwtDecoder implements ReactiveJwtDecoder {

	private final Charset jsonTokenStringCharset;

	private final Base64.Decoder decoder = Base64.getUrlDecoder();

	private final Map<String, ReactiveJwtDecoder> delegates;

	public ReactiveMultiAuthorizationServersJwtDecoder(Collection<String> locations, Charset jsonTokenStringCharset) {
		this.jsonTokenStringCharset = jsonTokenStringCharset;
		delegates = locations.stream().collect(Collectors.toMap(location -> location, ReactiveJwtDecoders::fromOidcIssuerLocation));
	}

	@SuppressWarnings("unchecked")
	@Override
	public Mono<Jwt> decode(String token) throws JwtException {
		final var chunks = token.split("\\.");
		if (chunks.length < 3) {
			throw new JwtException(String.format("Malformed encoded JWT: %s", token));
		}
		final var decodedPayload = new String(decoder.decode(chunks[1]), jsonTokenStringCharset);
		Map<String, Object> json;
		try {
			json = new ObjectMapper().readValue(decodedPayload, Map.class);
		} catch (final IOException e) {
			throw new JwtException(String.format("Malformed JWT payload: %s", chunks[1]));
		}
		final var issuer = json.get(IdTokenClaimNames.ISS).toString();

		final var delegate = delegates.get(issuer);
		if (delegate == null) {
			throw new JwtException(String.format("Unsupported issuer: %s", issuer));
		}
		return delegate.decode(token);
	}
}
