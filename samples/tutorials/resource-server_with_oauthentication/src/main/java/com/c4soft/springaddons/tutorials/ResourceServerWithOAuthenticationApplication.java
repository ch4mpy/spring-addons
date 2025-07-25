package com.c4soft.springaddons.tutorials;

import java.util.Collection;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.OpenidToken;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JwtAbstractAuthenticationTokenConverter;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@SecurityScheme(name = "authorization-code", type = SecuritySchemeType.OAUTH2,
    flows = @OAuthFlows(authorizationCode = @OAuthFlow(
        authorizationUrl = "https://oidc.c4-soft.com/auth/realms/master/protocol/openid-connect/auth",
        tokenUrl = "https://oidc.c4-soft.com/auth/realms/master/protocol/openid-connect/token",
        scopes = {@OAuthScope(name = "openid"), @OAuthScope(name = "profile")})))
@SpringBootApplication
public class ResourceServerWithOAuthenticationApplication {

  public static void main(String[] args) {
    SpringApplication.run(ResourceServerWithOAuthenticationApplication.class, args);
  }

  @Configuration
  @EnableMethodSecurity
  public static class SecurityConfig {
    @Bean
    JwtAbstractAuthenticationTokenConverter authenticationConverter(
        Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
        OpenidProviderPropertiesResolver opPropertiesResolver) {
      return jwt -> {
        final var opProperties = opPropertiesResolver.resolve(jwt.getClaims())
            .orElseThrow(() -> new NotAConfiguredOpenidProviderException(jwt.getClaims()));
        final var accessToken =
            new OpenidToken(new OpenidClaimSet(jwt.getClaims(), opProperties.getUsernameClaim()),
                jwt.getTokenValue());
        final var authorities = authoritiesConverter.convert(jwt.getClaims());
        return new OAuthentication<>(accessToken, authorities);
      };
    }

    @Bean
    ResourceServerExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
      // @formatter:off
            return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                    .requestMatchers(PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/actuator/**")).hasAuthority("OBSERVABILITY:read")
                    .requestMatchers(PathPatternRequestMatcher.pathPattern("/actuator/**")).hasAuthority("OBSERVABILITY:write")
                    .anyRequest().authenticated();
            // @formatter:on
    }
  }

}
