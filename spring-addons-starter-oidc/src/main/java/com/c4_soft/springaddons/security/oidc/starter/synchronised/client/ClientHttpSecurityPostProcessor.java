package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import com.c4_soft.springaddons.security.oidc.starter.synchronised.HttpSecurityPostProcessor;

/**
 * A post-processor to override anything from spring-addons client security filter-chain auto-configuration.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public interface ClientHttpSecurityPostProcessor extends HttpSecurityPostProcessor {
}