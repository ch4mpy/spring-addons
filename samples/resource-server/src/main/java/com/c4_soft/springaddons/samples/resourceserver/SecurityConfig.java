package com.c4_soft.springaddons.samples.resourceserver;

import java.util.Collection;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JwtAbstractAuthenticationTokenConverter;

/**
 * <p>
 * The security filter chain, the JWT decoders (one per trusted issuer, built lazily), the
 * authorities converter, CORS and access control for public routes are all auto-configured from
 * properties: this class only enables method security and overrides <b>one</b> of the auto-configured
 * beans.
 * </p>
 * <p>
 * Almost everything spring-addons-starter-oidc defines is {@code @ConditionalOnMissingBean}: an
 * application replaces just the bean it needs to, and keeps the rest of the auto-configuration. The
 * bean below switches the {@code Authentication} implementation from Spring's
 * {@code JwtAuthenticationToken} to {@link OAuthentication OAuthentication&lt;OpenidToken&gt;}, which
 * exposes typed accessors to OpenID claims ({@code getAttributes().getPreferredUsername()},
 * {@code getEmail()}, ...) and the original Bearer string ({@code getBearerHeader()}). Delete it
 * to get {@code JwtAuthenticationToken} back.
 * </p>
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  @Bean
  JwtAbstractAuthenticationTokenConverter authenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
      OpenidProviderPropertiesResolver opPropertiesResolver) {
    return jwt -> {
      // the username claim is configured per issuer (preferred_username for Keycloak, sub by default)
      final var usernameClaim = opPropertiesResolver.resolve(jwt.getClaims())
          .orElseThrow(() -> new NotAConfiguredOpenidProviderException(jwt.getClaims()))
          .getUsernameClaim();
      final var token = new OpenidToken(jwt.getClaims(), usernameClaim, jwt.getTokenValue());
      // the authorities converter is the auto-configured one: it maps the claims listed in
      // com.c4-soft.springaddons.oidc.ops[].authorities for the token issuer
      return new OAuthentication<>(token, authoritiesConverter.convert(jwt.getClaims()));
    };
  }
}
