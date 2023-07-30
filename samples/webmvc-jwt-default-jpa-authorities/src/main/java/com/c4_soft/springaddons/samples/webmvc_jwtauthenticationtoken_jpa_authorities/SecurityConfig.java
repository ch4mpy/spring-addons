package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken_jpa_authorities;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
	@Bean
	ResourceServerExpressionInterceptUrlRegistryPostProcessor expressionInterceptUrlRegistryPostProcessor() {
		// @formatter:off
        return (AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry) -> registry
                .requestMatchers(new AntPathRequestMatcher("/secured-route")).hasRole("AUTHORIZED_PERSONNEL")
                .anyRequest().authenticated();
        // @formatter:on
	}

	@Bean
	ClaimSetAuthoritiesConverter authoritiesConverter(UserAuthorityRepository authoritiesRepo) {
		return new PersistedGrantedAuthoritiesRetriever(authoritiesRepo);
	}
}