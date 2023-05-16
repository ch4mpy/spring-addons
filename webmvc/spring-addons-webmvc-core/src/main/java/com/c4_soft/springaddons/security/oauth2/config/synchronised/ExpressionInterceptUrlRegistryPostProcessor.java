package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

/**
 * Customize access-control for routes which where not listed in {@link SpringAddonsSecurityProperties#permitAll}
 * 
 * @author ch4mp
 */
public interface ExpressionInterceptUrlRegistryPostProcessor {
	AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry
			authorizeHttpRequests(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry);
}
