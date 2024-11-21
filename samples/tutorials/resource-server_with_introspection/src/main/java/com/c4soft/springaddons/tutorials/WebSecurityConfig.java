package com.c4soft.springaddons.tutorials;

import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.OpenidToken;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

  @Bean
  @Profile("oauthentication")
  // This bean is optional as a default one is provided (building a
  // BearerAuthenticationToken)
  OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
    return (String introspectedToken,
        OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> new OAuthentication<>(
            new OpenidToken(new OpenidClaimSet(authenticatedPrincipal.getAttributes()),
                introspectedToken),
            authoritiesConverter.convert(authenticatedPrincipal.getAttributes()));
  }

  @Component
  @Profile("auth0 | cognito")
  public static class UserEndpointOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
    private final URI userinfoUri;
    private final RestTemplate restClient = new RestTemplate();

    public UserEndpointOpaqueTokenIntrospector(OAuth2ResourceServerProperties oauth2Properties)
        throws IOException {
      userinfoUri = URI.create(oauth2Properties.getOpaquetoken().getIntrospectionUri());
    }

    @Override
    @SuppressWarnings("unchecked")
    public OAuth2AuthenticatedPrincipal introspect(String token) {
      HttpHeaders headers = new HttpHeaders();
      headers.setBearerAuth(token);
      final var claims = new OpenidClaimSet(restClient
          .exchange(userinfoUri, HttpMethod.GET, new HttpEntity<>(headers), Map.class).getBody());
      // No need to map authorities there, it is done later by
      // OpaqueTokenAuthenticationConverter
      return new OAuth2IntrospectionAuthenticatedPrincipal(claims, List.of());
    }

  }
}
