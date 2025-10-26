package com.c4_soft.springaddons.security.oidc.starter.synchronised;

import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/**
 * Customize the servlet csrf token repository configured by spring-addons
 */
@FunctionalInterface
public interface CookieCsrfTokenRepositoryPostProcessor {
  CookieCsrfTokenRepository process(CookieCsrfTokenRepository repository);
}
