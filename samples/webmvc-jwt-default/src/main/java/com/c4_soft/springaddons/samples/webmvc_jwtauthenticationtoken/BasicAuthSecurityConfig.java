package com.c4_soft.springaddons.samples.webmvc_jwtauthenticationtoken;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * <p>
 * This is just for demonstration purpose for https://github.com/keycloak/keycloak/discussions/10187
 * </p>
 * <p>
 * Here, we add a security filter chain for requests with Basic authentication. The authentication
 * manager in this filter-chain first retrieves tokens using password-grant flow, and then delegates
 * to an OAuth2 authentication manger (after replacing the Basic Authorization header to a Bearer
 * one containing the just retrieved access token)
 * </p>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Profile("basic-authentication")
@Configuration
public class BasicAuthSecurityConfig {
}
