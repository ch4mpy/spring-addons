package org.springframework.security.test.support.openid;

import java.net.URI;
import java.time.Instant;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.Assert;

import com.c4soft.oauth2.ModifiableTokenProperties;

public class IdTokenBuilder {
	private String value;

	private final ModifiableTokenProperties claims = new ModifiableTokenProperties();

	public IdTokenBuilder value(String tokenValue) {
		this.value = tokenValue;
		return this;
	}

	public IdTokenBuilder issuer(URI issuer) {
		Assert.isTrue(issuer.getScheme().startsWith("https"), "issuer must use the https scheme");
		this.claims.put(IdTokenClaimNames.ISS, issuer.toString());
		return this;
	}

	public IdTokenBuilder subject(String name) {
		this.claims.put(IdTokenClaimNames.SUB, name);
		return this;
	}

	public IdTokenBuilder audience(String... audience) {
		this.claims.put(IdTokenClaimNames.AUD, Stream.of(audience).collect(Collectors.toList()));
		return this;
	}

	public IdTokenBuilder expiresAt(Instant expiresAt) {
		this.claims.put(IdTokenClaimNames.EXP, expiresAt.getEpochSecond());
		return this;
	}

	public IdTokenBuilder issuedAt(Instant issuedAt) {
		this.claims.put(IdTokenClaimNames.IAT, issuedAt.getEpochSecond());
		return this;
	}

	public IdTokenBuilder authenticatedAt(Instant authenticatedAt) {
		this.claims.put(IdTokenClaimNames.AUTH_TIME, authenticatedAt.getEpochSecond());
		return this;
	}

	public IdTokenBuilder acr(String acr) {
		this.claims.put(IdTokenClaimNames.ACR, acr);
		return this;
	}

	public IdTokenBuilder amr(String... amr) {
		this.claims.put(IdTokenClaimNames.AMR, amr);
		return this;
	}

	public IdTokenBuilder azp(String azp) {
		this.claims.put(IdTokenClaimNames.AZP, azp);
		return this;
	}

	public IdTokenBuilder claim(String name, Object value) {
		this.claims.put(name,  value);
		return this;
	}

	public IdTokenBuilder clearClaims() {
		this.claims.clear();
		return this;
	}

	public OidcIdToken build() {
		return new OidcIdToken(value, claims.getAsInstant(IdTokenClaimNames.IAT), claims.getAsInstant(IdTokenClaimNames.EXP), claims);
	}

}
