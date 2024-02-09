package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import com.c4_soft.springaddons.security.oidc.starter.synchronised.SynchronizedHttpSecurityPostProcessor;

/**
 * Process {@link HttpSecurity} of default security filter-chain after it was processed by spring-addons. This enables to override anything that was
 * auto-configured (or add to it).
 *
 * @author ch4mp
 */
public interface ResourceServerSynchronizedHttpSecurityPostProcessor extends SynchronizedHttpSecurityPostProcessor {
}
