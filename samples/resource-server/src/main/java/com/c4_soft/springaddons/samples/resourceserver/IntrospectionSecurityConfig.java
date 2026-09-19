package com.c4_soft.springaddons.samples.resourceserver;

import java.util.Collection;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidToken;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;

/**
 * <p>
 * Active with the {@code introspection} profile, which sets
 * {@code spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}: the auto-configured
 * filter chain then validates access tokens by calling the introspection endpoint of the
 * authorization server instead of decoding them locally with a JWT decoder.
 * </p>
 * <p>
 * The only thing the application has to change is <b>which</b> converter it exposes. The default
 * output of the starter would be a {@code BearerTokenAuthentication} instead of the
 * {@code JwtAuthenticationToken} of the JWT decoder; the converter below produces the very same
 * {@link OAuthentication OAuthentication&lt;OpenidToken&gt;} as {@link SecurityConfig} does with a
 * JWT decoder, so the controllers, the services and their tests are strictly unchanged.
 * </p>
 * <p>
 * Introspection means one call to the authorization server for <b>every</b> request it processes.
 * Prefer a JWT decoder unless something (immediate revocation, opaque tokens by design) really
 * requires it.
 * </p>
 */
@Profile("introspection")
@Configuration
public class IntrospectionSecurityConfig {

  @Bean
  OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
      OpenidProviderPropertiesResolver opPropertiesResolver) {
    return (String introspectedToken, OAuth2AuthenticatedPrincipal principal) -> {
      final var claims = principal.getAttributes();
      final var usernameClaim = opPropertiesResolver.resolve(claims)
          .orElseThrow(() -> new NotAConfiguredOpenidProviderException(claims)).getUsernameClaim();
      final var token = new OpenidToken(claims, usernameClaim, introspectedToken);
      return new OAuthentication<>(token, authoritiesConverter.convert(claims));
    };
  }
}
