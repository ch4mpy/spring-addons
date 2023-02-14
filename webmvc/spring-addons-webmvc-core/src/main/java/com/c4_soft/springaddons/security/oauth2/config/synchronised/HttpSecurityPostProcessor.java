package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Process {@link HttpSecurity} of default security filter-chain  after it was processed by spring-addons.
 * This enables to override anything that was auto-configured (or add to it).
 * 
 * @author ch4mp
 *
 */
public interface HttpSecurityPostProcessor {
	HttpSecurity process(HttpSecurity httpSecurity) throws Exception;
}
