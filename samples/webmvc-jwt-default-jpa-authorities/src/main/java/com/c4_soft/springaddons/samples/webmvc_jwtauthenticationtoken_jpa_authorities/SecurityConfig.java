package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ResourceServerExpressionInterceptUrlRegistryPostProcessor;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    ResourceServerExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
        // @formatter:off
        return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                .requestMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
                .anyRequest().authenticated();
        // @formatter:on
    }

    @Bean
    OAuth2AuthoritiesConverter authoritiesConverter(UserAuthorityRepository authoritiesRepo) {
        return new PersistedGrantedAuthoritiesRetriever(authoritiesRepo);
    }
}