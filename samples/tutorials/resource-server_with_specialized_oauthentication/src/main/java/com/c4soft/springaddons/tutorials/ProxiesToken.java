package com.c4soft.springaddons.tutorials;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.OpenidToken;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ProxiesToken extends OpenidToken {
  private static final long serialVersionUID = 2859979941152449048L;

  private final Map<String, Proxy> proxies;

  public ProxiesToken(Map<String, Object> claims, String tokenValue) {
    super(claims, StandardClaimNames.PREFERRED_USERNAME, tokenValue);
    this.proxies = Collections
        .unmodifiableMap(Optional.ofNullable(proxiesConverter.convert(this)).orElse(Map.of()));
  }

  public Proxy getProxyFor(String username) {
    return proxies.getOrDefault(username, new Proxy(username, getName(), List.of()));
  }

  private static final Converter<OpenidClaimSet, Map<String, Proxy>> proxiesConverter = claims -> {
    @SuppressWarnings("unchecked")
    final var proxiesClaim = (Map<String, List<String>>) claims.get("proxies");
    if (proxiesClaim == null) {
      return Map.of();
    }
    return proxiesClaim.entrySet().stream()
        .map(e -> new Proxy(e.getKey(), claims.getPreferredUsername(), e.getValue()))
        .collect(Collectors.toMap(Proxy::getProxiedUsername, p -> p));
  };
}
