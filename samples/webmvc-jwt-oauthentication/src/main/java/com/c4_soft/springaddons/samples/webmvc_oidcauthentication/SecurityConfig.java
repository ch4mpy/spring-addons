package com.c4_soft.springaddons.samples.webmvc_oidcauthentication;

import java.util.Collection;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.c4_soft.springaddons.security.oidc.OAuthentication;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.JwtAbstractAuthenticationTokenConverter;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    JwtAbstractAuthenticationTokenConverter authenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
            OpenidProviderPropertiesResolver opPropertiesResolver) {
        return jwt -> new OAuthentication<>(
            new OpenidClaimSet(
                jwt.getClaims(),
                opPropertiesResolver.resolve(jwt.getClaims()).orElseThrow(() -> new NotAConfiguredOpenidProviderException(jwt.getClaims())).getUsernameClaim()),
            authoritiesConverter.convert(jwt.getClaims()),
            jwt.getTokenValue());

    }

    @Bean
    ResourceServerExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
        // @formatter:off
        return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                .requestMatchers(new AntPathRequestMatcher("/secured-route")).hasRole("AUTHORIZED_PERSONNEL")
                .anyRequest().authenticated();
        // @formatter:on
    }
}
