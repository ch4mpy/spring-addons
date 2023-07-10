package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import com.c4_soft.springaddons.security.oidc.starter.reactive.AuthorizeExchangeSpecPostProcessor;

/**
 * Customize access-control for routes which where not listed in
 * {@link com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties#permitAll SpringAddonsOidcClientProperties::permit-all} or
 * {@link com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcResourceServerProperties#permitAll
 * SpringAddonsOidcResourceServerProperties::permit-all}
 *
 * @author ch4mp
 */
public interface ResourceServerAuthorizeExchangeSpecPostProcessor extends AuthorizeExchangeSpecPostProcessor {
}