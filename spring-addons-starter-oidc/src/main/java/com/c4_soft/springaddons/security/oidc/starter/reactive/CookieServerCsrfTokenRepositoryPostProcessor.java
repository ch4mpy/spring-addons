package com.c4_soft.springaddons.security.oidc.starter.reactive;

import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;

/**
 * Customize the reactive csrf token repository configured by spring-addons
 */
@FunctionalInterface
public interface CookieServerCsrfTokenRepositoryPostProcessor {
  CookieServerCsrfTokenRepository process(CookieServerCsrfTokenRepository repository);
}
