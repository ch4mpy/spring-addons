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
import org.springframework.security.oauth2.jwt.JwtClaimNames;

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ResourceServerExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.OAuth2AuthenticationFactory;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.OAuthFlow;
import io.swagger.v3.oas.annotations.security.OAuthFlows;
import io.swagger.v3.oas.annotations.security.OAuthScope;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

@SecurityScheme(name = "authorization-code", type = SecuritySchemeType.OAUTH2, flows = @OAuthFlows(authorizationCode = @OAuthFlow(authorizationUrl = "https://localhost:8443/realms/master/protocol/openid-connect/auth", tokenUrl = "https://localhost:8443/realms/master/protocol/openid-connect/token", scopes = {
        @OAuthScope(name = "openid"), @OAuthScope(name = "profile") })))
@SpringBootApplication
public class ResourceServerWithOAuthenticationApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerWithOAuthenticationApplication.class, args);
    }

    @Configuration
    @EnableMethodSecurity
    public static class SecurityConfig {
        @Bean
        OAuth2AuthenticationFactory authenticationFactory(
                Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
                SpringAddonsSecurityProperties addonsProperties) {
            return (bearerString, claims) -> new OAuthentication<>(
                    new OpenidClaimSet(
                            claims,
                            addonsProperties.getIssuerProperties(claims.get(JwtClaimNames.ISS))
                                    .getUsernameClaim()),
                    authoritiesConverter.convert(claims),
                    bearerString);
        }

        @Bean
        ResourceServerExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
            // @formatter:off
            return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                    .requestMatchers(HttpMethod.GET, "/actuator/**").hasAuthority("OBSERVABILITY:read")
                    .requestMatchers("/actuator/**").hasAuthority("OBSERVABILITY:write")
                    .anyRequest().authenticated();
            // @formatter:on
        }
    }

}
