package com.c4_soft.springaddons.security.oidc.starter.properties;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * <p>
 * Configuration properties for OAuth2 auto-configuration extensions to spring-boot-starter-oauth2-client and spring-boot-starter-oauth2-resource-server.
 * </p>
 * The following spring-boot standard properties are used:
 * <ul>
 * <li>spring.security.oauth2.client.provider.*</li>
 * <li>spring.security.oauth2.client.registration.*</li>
 * <li>spring.security.oauth2.resourceserver.opaquetoken.*</li>
 * </ul>
 * <b>spring.security.oauth2.resourceserver.jwt.* properties are ignored.</b> The reason for that is it is applicable only to single tenant scenarios. Use
 * properties
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.oidc")
public class SpringAddonsOidcProperties {

    /**
     * OpenID Providers configuration: JWK set URI, issuer URI, audience, and authorities mapping configuration for each issuer. A minimum of one issuer is
     * required. <b>Properties defined here are a replacement for spring.security.oauth2.resourceserver.jwt.*</b> (which will be ignored). Authorities mapping
     * defined there is used by both client and resource server filter-chains.
     */
    private List<OpenidProviderProperties> ops = List.of();

    /**
     * Auto-configuration for an OAuth2 client (secured with session, not access token) Security(Web)FilterChain with &#64;Order(Ordered.LOWEST_PRECEDENCE - 1).
     * Typical use-cases are spring-cloud-gateway used as BFF and applications with Thymeleaf or another server-side rendering framework. Default configuration
     * includes: enabled sessions, CSRF protection, "oauth2Login", "logout". securityMatchers must be set for this filter-chain &#64;Bean and its dependencies
     * to be defined. <b>Properties defined here are a complement for spring.security.oauth2.client.*</b> (which are required when enabling spring-addons client
     * filter-chain).
     */
    private SpringAddonsOidcClientProperties client = new SpringAddonsOidcClientProperties();

    /**
     * Auto-configuration for an OAuth2 resource server Security(Web)FilterChain with &#64;Order(LOWEST_PRECEDENCE). Typical use case is a REST API secured with
     * access tokens. Default configuration is as follow: no securityMatcher to process all the requests that were not intercepted by higher &#64;Order
     * Security(Web)FilterChains, no session, disabled CSRF protection, and 401 to unauthorized requests.
     */
    private SpringAddonsOidcResourceServerProperties resourceserver = new SpringAddonsOidcResourceServerProperties();

    /**
     * @param iss the issuer URI string
     * @return configuration properties associated with the provided issuer URI
     * @throws MissingAuthorizationServerConfigurationException if configuration properties don not have an entry for the exact issuer (even trailing slash is
     *             important)
     */
    public OpenidProviderProperties getOpProperties(String iss) throws MissingAuthorizationServerConfigurationException {
        return ops
            .stream()
            .filter(issuerProps -> Objects.equals(Optional.ofNullable(issuerProps.getIss()).map(URI::toString).orElse(null), iss))
            .findAny()
            .orElseThrow(() -> new MissingAuthorizationServerConfigurationException(iss));
    }

    /**
     * @param iss the issuer URL
     * @return configuration properties associated with the provided issuer URI
     * @throws MissingAuthorizationServerConfigurationException if configuration properties don not have an entry for the exact issuer (even trailing slash is
     *             important)
     */
    public OpenidProviderProperties getOpProperties(Object iss) throws MissingAuthorizationServerConfigurationException {
        if (iss == null && ops.size() == 1) {
            return ops.get(0);
        }
        return getOpProperties(Optional.ofNullable(iss).map(Object::toString).orElse(null));
    }

}
