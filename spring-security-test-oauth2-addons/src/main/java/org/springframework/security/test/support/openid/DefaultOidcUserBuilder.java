package org.springframework.security.test.support.openid;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class DefaultOidcUserBuilder {
	public static final Set<String> OPENID_STANDARD_CLAIM_NAMES;
	static {
		final var standardClaimNames = new StandardClaimNames() {};

		OPENID_STANDARD_CLAIM_NAMES = Stream.of(StandardClaimNames.class.getDeclaredFields()).map(f -> {
			try {
				return f.get(standardClaimNames).toString();
			} catch (IllegalArgumentException | IllegalAccessException e) {
				throw new RuntimeException(e);
			}
		}).collect(Collectors.toSet());
	}

	private String nameAttributeKey;
	private final Map<String, Object> userInfo;

	public DefaultOidcUserBuilder() {
		this.userInfo = new HashMap<>();
		this.nameAttributeKey = StandardClaimNames.NAME;
	}

	public DefaultOidcUserBuilder nameAttributeKey(String nameAttributeKey) {
		Assert.hasLength(nameAttributeKey, "nameAttributeKey can't be empty");
		if(hasName() && !nameAttributeKey.equals(this.nameAttributeKey)) {
			this.userInfo.put(nameAttributeKey, this.userInfo.get(this.nameAttributeKey));
			this.userInfo.remove(this.nameAttributeKey);
		}
		this.nameAttributeKey = nameAttributeKey;
		return this;
	}

	public String getNameAttributeKey() {
		return this.nameAttributeKey;
	}

	public DefaultOidcUserBuilder name(String name) {
		this.userInfo.put(this.nameAttributeKey, name);
		return this;
	}

	public boolean hasName() {
		return this.userInfo.containsKey(this.nameAttributeKey) && StringUtils.hasLength(this.userInfo.get(this.nameAttributeKey).toString());
	}

	public DefaultOidcUserBuilder subject(String subject) {
		this.userInfo.put(StandardClaimNames.SUB, subject);
		return this;
	}

	public DefaultOidcUserBuilder email(String email) {
		this.userInfo.put(StandardClaimNames.EMAIL, email);
		return this;
	}

	public DefaultOidcUserBuilder emailVerified(boolean emailVerified) {
		this.userInfo.put(StandardClaimNames.EMAIL_VERIFIED, emailVerified);
		return this;
	}

	/**
	 * Add a claim to userInfo
	 * @param name userInfo claim name
	 * @param value userInfo claim value
	 * @return this builder to further configure
	 */
	public DefaultOidcUserBuilder userInfo(String name, Object value) {
		this.userInfo.put(name, value);
		return this;
	}

	public Map<String, Object> getUserInfo() {
		return Collections.unmodifiableMap(this.userInfo);
	}

	public DefaultOidcUser build(Collection<GrantedAuthority> authorities, OidcIdToken oidcIdToken) {
		return new DefaultOidcUser(authorities, oidcIdToken, new OidcUserInfo(userInfo), nameAttributeKey);
	}

	public Set<String> getOpenidScopes() {
		return this.userInfo.keySet().stream()
				.filter(OPENID_STANDARD_CLAIM_NAMES::contains)
				.collect(Collectors.toSet());
	}

	public Set<String> getRequestClaims() {
		return this.userInfo.keySet().stream().filter(claimName -> !OPENID_STANDARD_CLAIM_NAMES.contains(claimName)).collect(Collectors.toSet());
	}

}
