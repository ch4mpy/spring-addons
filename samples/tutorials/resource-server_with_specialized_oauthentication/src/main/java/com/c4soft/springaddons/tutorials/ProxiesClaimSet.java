package com.c4soft.springaddons.tutorials;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ProxiesClaimSet extends OpenidClaimSet {
	private static final long serialVersionUID = 38784488788537111L;

	private final Map<String, Proxy> proxies;

	public ProxiesClaimSet(Map<String, Object> claims) {
		super(claims);
		this.proxies = Collections.unmodifiableMap(Optional.ofNullable(proxiesConverter.convert(this)).orElse(Collections.emptyMap()));
	}

	public Proxy getProxyFor(String username) {
		return proxies.getOrDefault(username, new Proxy(username, getName(), Collections.emptyList()));
	}

	private static final Converter<OpenidClaimSet, Map<String, Proxy>> proxiesConverter = claims -> {
		if (claims == null) {
			return Collections.emptyMap();
		}
		@SuppressWarnings("unchecked")
		final Map<String, List<String>> proxiesClaim = (Map<String, List<String>>) claims.get("proxies");
		if (proxiesClaim == null) {
			return Collections.emptyMap();
		}
		return proxiesClaim.entrySet().stream().map(e -> new Proxy(e.getKey(), claims.getPreferredUsername(), e.getValue()))
				.collect(Collectors.toMap(Proxy::getProxiedUsername, p -> p));
	};
}
