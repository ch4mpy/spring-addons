package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Objects;
import org.springframework.security.core.GrantedAuthority;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class ProxiesAuthentication extends OAuthentication<ProxiesToken> {
  private static final long serialVersionUID = 447991554788295331L;

  public ProxiesAuthentication(ProxiesToken token,
      Collection<? extends GrantedAuthority> authorities) {
    super(token, authorities);
  }

  public boolean hasName(String username) {
    return Objects.equals(getName(), username);
  }

  public Proxy getProxyFor(String username) {
    return getAttributes().getProxyFor(username);
  }
}
