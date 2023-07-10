package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.springaddons.security.oidc.OAuthentication;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ProxiesAuthentication extends OAuthentication<ProxiesClaimSet> {
	private static final long serialVersionUID = -6247121748050239792L;

	public ProxiesAuthentication(ProxiesClaimSet claims, Collection<? extends GrantedAuthority> authorities, String tokenString) {
		super(claims, authorities, tokenString);
	}

	@Override
	public String getName() {
		return Optional.ofNullable(super.getAttributes().getPreferredUsername()).orElse(super.getAttributes().getSubject());
	}

	public boolean hasName(String username) {
		return Objects.equals(getName(), username);
	}

	public Proxy getProxyFor(String username) {
		return getAttributes().getProxyFor(username);
	}

}
