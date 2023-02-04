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

import com.c4_soft.springaddons.security.oauth2.OAuthentication;
import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.OAuth2AuthenticationFactory;

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
                Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
            return (bearerString, claims) -> new OAuthentication<>(new OpenidClaimSet(claims),
                    authoritiesConverter.convert(claims), bearerString);
        }

        @Bean
        ExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
            // @formatter:off
            return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                    .requestMatchers(HttpMethod.GET, "/actuator/**").hasAuthority("OBSERVABILITY:read")
                    .requestMatchers("/actuator/**").hasAuthority("OBSERVABILITY:write")
                    .anyRequest().authenticated();
            // @formatter:on
        }
    }

}
