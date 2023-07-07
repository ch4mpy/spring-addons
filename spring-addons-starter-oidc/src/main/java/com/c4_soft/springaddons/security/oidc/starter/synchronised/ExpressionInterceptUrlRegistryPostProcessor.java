package com.c4_soft.springaddons.security.oidc.starter.synchronised;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcResourceServerProperties;

/**
 * Customize access-control for routes which where not listed in {@link SpringAddonsOidcClientProperties#permitAll} or
 * {@link SpringAddonsOidcResourceServerProperties#permitAll}
 *
 * @author ch4mp
 */
public interface ExpressionInterceptUrlRegistryPostProcessor {
	AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry
			authorizeHttpRequests(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry);
}
