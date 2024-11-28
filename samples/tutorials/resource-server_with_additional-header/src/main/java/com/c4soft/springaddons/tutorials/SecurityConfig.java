package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.OpenidToken;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.HttpServletRequestSupport;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.HttpServletRequestSupport.InvalidHeaderException;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JwtAbstractAuthenticationTokenConverter;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
  public static final String ID_TOKEN_HEADER_NAME = "X-ID-Token";
  private static final Map<String, JwtDecoder> idTokenDecoders = new ConcurrentHashMap<>();

  private JwtDecoder getJwtDecoder(Map<String, Object> accessClaims) {
    if (accessClaims == null) {
      return null;
    }
    final var iss =
        Optional.ofNullable(accessClaims.get(JwtClaimNames.ISS)).map(Object::toString).orElse(null);
    if (iss == null) {
      return null;
    }
    if (!idTokenDecoders.containsKey(iss)) {
      idTokenDecoders.put(iss, JwtDecoders.fromIssuerLocation(iss));
    }
    return idTokenDecoders.get(iss);
  }

  @Bean
  JwtAbstractAuthenticationTokenConverter authenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
    return jwt -> {
      try {
        final var jwtDecoder = getJwtDecoder(jwt.getClaims());
        final var authorities = authoritiesConverter.convert(jwt.getClaims());
        final var idTokenString =
            HttpServletRequestSupport.getUniqueRequestHeader(ID_TOKEN_HEADER_NAME);
        final var idToken = jwtDecoder == null ? null : jwtDecoder.decode(idTokenString);

        return new MyAuth(authorities, jwt.getTokenValue(), new OpenidClaimSet(jwt.getClaims()),
            idTokenString, new OpenidClaimSet(idToken.getClaims()));
      } catch (JwtException e) {
        throw new InvalidHeaderException(ID_TOKEN_HEADER_NAME);
      }
    };
  }

  @Bean
  ResourceServerExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
    // @formatter:off
    return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
        .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/actuator/**")).hasAuthority("OBSERVABILITY:read")
        .requestMatchers(new AntPathRequestMatcher("/actuator/**")).hasAuthority("OBSERVABILITY:write")
        .anyRequest().authenticated();
    // @formatter:on
  }

  @Data
  @EqualsAndHashCode(callSuper = true)
  public static class MyAuth extends OAuthentication<OpenidToken> {
    private static final long serialVersionUID = 1734079415899000362L;
    private final OpenidToken idToken;

    public MyAuth(Collection<? extends GrantedAuthority> authorities, String accessTokenString,
        OpenidClaimSet accessClaims, String idTokenString, OpenidClaimSet idClaims) {
      super(new OpenidToken(accessClaims, accessTokenString), authorities);
      this.idToken = new OpenidToken(idClaims, idTokenString);
    }

  }
}
