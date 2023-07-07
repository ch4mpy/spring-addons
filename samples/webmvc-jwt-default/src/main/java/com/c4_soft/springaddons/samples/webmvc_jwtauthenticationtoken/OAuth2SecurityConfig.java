package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;

@Configuration
@EnableMethodSecurity
public class OAuth2SecurityConfig {
	@Bean
	ResourceServerExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
		// @formatter:off
        return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                .requestMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
                .anyRequest().authenticated();
        // @formatter:on
	}
}