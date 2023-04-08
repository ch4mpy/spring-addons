package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * A post-processor to override anything from spring-addons client security
 * filter-chain auto-configuration.
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 *
 */
public interface ClientHttpSecurityPostProcessor {
    HttpSecurity process(HttpSecurity httpSecurity) throws Exception;
}