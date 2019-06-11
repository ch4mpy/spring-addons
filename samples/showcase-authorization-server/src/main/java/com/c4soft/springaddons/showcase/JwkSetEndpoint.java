package com.c4soft.springaddons.showcase;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;

import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Legacy Authorization Server (spring-security-oauth2) does not support any <a href target="_blank"
 * href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> endpoint.
 *
 * This class adds ad-hoc support in order to better support the other samples in the repo.
 */
@FrameworkEndpoint
@Profile("jwt")
class JwkSetEndpoint {
	KeyPair keyPair;

	public JwkSetEndpoint(KeyPair keyPair) {
		this.keyPair = keyPair;
	}

	@GetMapping("/.well-known/jwks.json")
	@ResponseBody
	public Map<String, Object> getKey() {
		JWK jwk =
				new RSAKey
						.Builder((RSAPublicKey) keyPair.getPublic())
						.privateKey((RSAPrivateKey) keyPair.getPrivate())
						.keyUse(KeyUse.SIGNATURE)
						.keyID(UUID.randomUUID().toString())
						.build();
		return new JWKSet(jwk).toJSONObject();
	}
}