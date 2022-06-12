package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;

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
		return super.getClaims().getPreferredUsername();
	}

	public Map<String, Proxy> getProxies() {
		return getClaims().getProxies();
	}

}
