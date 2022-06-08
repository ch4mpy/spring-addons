package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class MyAuthentication extends OidcAuthentication<OidcToken> {
	private static final long serialVersionUID = 6856299734098317908L;

	private final Map<String, Proxy> proxies;

	public MyAuthentication(OidcToken token, Collection<? extends GrantedAuthority> authorities, Map<String, Proxy> proxies, String bearerString) {
		super(token, authorities, bearerString);
		this.proxies = Collections.unmodifiableMap(proxies);
	}

	public Proxy getProxyFor(String proxiedUserSubject) {
		return this.proxies.getOrDefault(proxiedUserSubject, new Proxy(proxiedUserSubject, getToken().getSubject(), List.of()));
	}
}