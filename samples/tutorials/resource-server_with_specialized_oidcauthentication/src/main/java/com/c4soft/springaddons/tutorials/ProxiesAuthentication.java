package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;

import com.c4_soft.springaddons.security.oauth2.oidc.OidcAuthentication;
import com.c4_soft.springaddons.security.oauth2.oidc.OidcToken;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ProxiesAuthentication extends OidcAuthentication<OidcToken> {
	private static final long serialVersionUID = 6856299734098317908L;

	private final Map<String, Proxy> proxies;

	public ProxiesAuthentication(OidcToken token, Collection<? extends GrantedAuthority> authorities, Collection<Proxy> proxies, String bearerString) {
		super(token, authorities, bearerString);
		this.proxies = Collections.unmodifiableMap(proxies.stream().collect(Collectors.toMap(Proxy::getProxiedUsername, p -> p)));
	}

	@Override
	public String getName() {
		return getToken().getPreferredUsername();
	}

	public boolean is(String username) {
		return Objects.equals(getName(), username);
	}

	public Proxy getProxyFor(String username) {
		return this.proxies.getOrDefault(username, new Proxy(username, getName(), List.of()));
	}
}