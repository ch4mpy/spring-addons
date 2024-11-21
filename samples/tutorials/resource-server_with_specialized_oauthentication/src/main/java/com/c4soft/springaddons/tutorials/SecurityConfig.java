package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import com.c4_soft.springaddons.security.oidc.spring.SpringAddonsMethodSecurityExpressionHandler;
import com.c4_soft.springaddons.security.oidc.spring.SpringAddonsMethodSecurityExpressionRoot;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JwtAbstractAuthenticationTokenConverter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  @Bean
  JwtAbstractAuthenticationTokenConverter authenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
    return jwt -> {
      final var claimSet = new ProxiesToken(jwt.getClaims(), jwt.getTokenValue());
      return new ProxiesAuthentication(claimSet, authoritiesConverter.convert(claimSet));
    };
  }

  @Bean
  static MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
    return new SpringAddonsMethodSecurityExpressionHandler(
        ProxiesMethodSecurityExpressionRoot::new);
  }

  static final class ProxiesMethodSecurityExpressionRoot
      extends SpringAddonsMethodSecurityExpressionRoot {

    public boolean is(String preferredUsername) {
      return Objects.equals(preferredUsername, getAuthentication().getName());
    }

    public Proxy onBehalfOf(String proxiedUsername) {
      return get(ProxiesAuthentication.class).map(a -> a.getProxyFor(proxiedUsername))
          .orElse(new Proxy(proxiedUsername, getAuthentication().getName(), List.of()));
    }

    public boolean isNice() {
      return hasAnyAuthority("NICE", "SUPER_COOL");
    }
  }
}
