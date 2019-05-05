package org.springframework.security.test.support.openid;

import java.net.URL;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class IdTokenBuilder implements IdTokenClaimAccessor {
	private static final Set<String> ID_TOKEN_CLAIMS;

	static {
		final var idTokenClaimNames = new IdTokenClaimNames() {};
		ID_TOKEN_CLAIMS = Stream.of(IdTokenClaimNames.class.getDeclaredFields()).map(f -> {
			try {
				return f.get(idTokenClaimNames).toString();
			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new RuntimeException(e);
			}
		}).collect(Collectors.toSet());
	}

	private String value;

	private final Map<String, Object> claims = new HashMap<>();

	public IdTokenBuilder value(String tokenValue) {
		this.value = tokenValue;
		return this;
	}

	public IdTokenBuilder issuer(URL issuer) {
		Assert.isTrue(issuer.getProtocol().startsWith("https"), "issuer must use the https scheme");
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

	@Override
	public Map<String, Object> getClaims() {
		return claims;
	}

	public Set<String> getOpenidScopes() {
		return this.claims.keySet().stream()
				.filter(DefaultOidcUserBuilder.OPENID_STANDARD_CLAIM_NAMES::contains)
				.filter(name -> !ID_TOKEN_CLAIMS.contains(name))
				.collect(Collectors.toSet());
	}

	public boolean hasIssuer() {
		return StringUtils.hasLength(getClaimAsString(IdTokenClaimNames.ISS));
	}

	public boolean hasSubscriber() {
		return StringUtils.hasLength(getClaimAsString(IdTokenClaimNames.SUB));
	}

	public boolean hasAudience() {
		final List<String> audience = getClaimAsStringList(IdTokenClaimNames.AUD);
		return audience != null && audience.size() > 0;
	}

	public boolean hasIssuedAt() {
		return getClaimAsInstant(IdTokenClaimNames.IAT) != null;
	}

	public boolean hasExpiresAt() {
		return getClaimAsInstant(IdTokenClaimNames.EXP) != null;
	}

	public boolean hasAuthenticatedAt() {
		return getClaimAsInstant(IdTokenClaimNames.AUTH_TIME) != null;
	}

	public boolean hasValue() {
		return StringUtils.hasLength(value);
	}

	public OidcIdToken build() {
		return new OidcIdToken(value, getClaimAsInstant(IdTokenClaimNames.IAT), getClaimAsInstant(IdTokenClaimNames.EXP), claims);
	}

}
