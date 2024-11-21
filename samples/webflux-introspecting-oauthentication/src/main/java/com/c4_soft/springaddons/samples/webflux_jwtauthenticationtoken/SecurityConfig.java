package com.c4_soft.springaddons.samples.webflux_jwtauthenticationtoken;

import java.util.Collection;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.OpenidToken;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ResourceServerAuthorizeExchangeSpecPostProcessor;
import reactor.core.publisher.Mono;

@EnableReactiveMethodSecurity()
@Configuration
public class SecurityConfig {

  @Bean
  ReactiveOpaqueTokenAuthenticationConverter authenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
      OpenidProviderPropertiesResolver opPropertiesResolver) {
    return (String introspectedToken,
        OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> Mono.just(new OAuthentication<>(
            new OpenidToken(
                new OpenidClaimSet(authenticatedPrincipal.getAttributes(),
                    opPropertiesResolver.resolve(authenticatedPrincipal.getAttributes())
                        .orElseThrow(() -> new NotAConfiguredOpenidProviderException(
                            authenticatedPrincipal.getAttributes()))
                        .getUsernameClaim()),
                introspectedToken),
            authoritiesConverter.convert(authenticatedPrincipal.getAttributes())));
  }

  @Bean
  ResourceServerAuthorizeExchangeSpecPostProcessor authorizeExchangeSpecPostProcessor() {
    // @formatter:off
		return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec
				.pathMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
				.anyExchange().authenticated();
		// @formatter:on
  }

}
