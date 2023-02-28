package com.c4_soft.springaddons.security.oauth2.config;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <p>
 * Would better be named "SpringAddonsOAuth2ResourceServerProperties" and use
 * "com.c4-soft.springaddons.security.resource-server" as prefix
 * to better distinguish it from {@link SpringAddonsOAuth2ClientProperties}. But
 * the later was created later and keeping this name and prefix prevents from
 * anoying breaking changes.
 * </p>
 *
 * Here are defaults:
 *
 * <pre>
 * com.c4-soft.springaddons.security.issuers[0].location=https://localhost:8443/realms/master
 * com.c4-soft.springaddons.security.issuers[0].authorities[0].path=realm_access.roles
 * com.c4-soft.springaddons.security.issuers[0].authorities[0].prefix=
 * com.c4-soft.springaddons.security.issuers[0].authorities[0].caze=UNCHANGED
 * com.c4-soft.springaddons.security.statless-sessions=true
 * com.c4-soft.springaddons.security.csrf-enabled=true
 * com.c4-soft.springaddons.security.permit-all=
 * com.c4-soft.springaddons.security.redirect-to-login-if-unauthorized-on-restricted-content=true
 * </pre>
 *
 * Default conf for CORS being an empty array, CORS is disabled. To enable it
 * (following is very permissive, define something more restrictive):
 *
 * <pre>
 * com.c4-soft.springaddons.security.cors[0].path=/**
 * </pre>
 *
 * @author ch4mp
 */
@Data
@AutoConfiguration
@ConfigurationProperties(prefix = "com.c4-soft.springaddons.security")
public class SpringAddonsSecurityProperties {
    private IssuerProperties[] issuers = {};

    private CorsProperties[] cors = {};

    private String[] permitAll = { "/actuator/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html",
            "/webjars/swagger-ui/**", "/favicon.ico" };

    private boolean redirectToLoginIfUnauthorizedOnRestrictedContent = false;

    private boolean statlessSessions = true;

    private Csrf csrf = Csrf.DEFAULT;

    /**
     * @param iss the issuer URI string
     * @return configuration properties associated with the provided issuer URI
     * @throws MissingAuthorizationServerConfigurationException if configuration
     *                                                          properties don not
     *                                                          have an entry for
     *                                                          the exact issuer
     *                                                          (even
     *                                                          trailing slash is
     *                                                          important)
     */
    public IssuerProperties getIssuerProperties(String iss) throws MissingAuthorizationServerConfigurationException {
        return Stream.of(issuers)
                .filter(issuerProps -> Objects
                        .equals(Optional.ofNullable(issuerProps.getLocation()).map(URI::toString).orElse(null), iss))
                .findAny().orElseThrow(() -> new MissingAuthorizationServerConfigurationException(iss));
    }

    /**
     * @param iss the issuer URL
     * @return configuration properties associated with the provided issuer URI
     * @throws MissingAuthorizationServerConfigurationException if configuration
     *                                                          properties don not
     *                                                          have an entry for
     *                                                          the exact issuer
     *                                                          (even
     *                                                          trailing slash is
     *                                                          important)
     */
    public IssuerProperties getIssuerProperties(Object iss) throws MissingAuthorizationServerConfigurationException {
        if (iss == null && issuers.length == 1) {
            return issuers[0];
        }
        return getIssuerProperties(Optional.ofNullable(iss).map(Object::toString).orElse(null));
    }

    @Data
    public static class CorsProperties {
        private String path = "/**";
        private String[] allowedOrigins = { "*" };
        private String[] allowedMethods = { "*" };
        private String[] allowedHeaders = { "*" };
        private String[] exposedHeaders = { "*" };
    }

    @Data
    public static class IssuerProperties {
        private URI location;
        private URI jwkSetUri;
        private SimpleAuthoritiesMappingProperties[] authorities = { new SimpleAuthoritiesMappingProperties() };

        /**
         * JSON path for the claim to use as "name" source
         */
        private String usernameClaim = StandardClaimNames.SUB;
    }

    /**
     * Configuration for {@link ConfigurableClaimSet2AuthoritiesConverter}
     *
     * @author ch4mp
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SimpleAuthoritiesMappingProperties {
        private String path = "$.realm_access.roles";
        private String prefix = "";
        private Case caze = Case.UNCHANGED;
    }

    public static enum Case {
        UNCHANGED, UPPER, LOWER
    }

    /**
     * <ul>
     * <li>DEFAULT switches to DISABLED if statlessSessions is true and Spring
     * default otherwise.</li>
     * <li>DISABLE disables CSRF protection.</li>
     * <li>SESSION stores CSRF token in servlet session or reactive web-session
     * (makes no sense if session-management is "stateless").</li>
     * <li>COOKIE_HTTP_ONLY stores CSRF in a http-only XSRF-TOKEN cookie (not
     * accessible from rich client apps).</li>
     * <li>COOKIE_ACCESSIBLE_FROM_JS stores CSRF in a XSRF-TOKEN cookie that is
     * readable by rich client apps.</li>
     * </ul>
     *
     * @author ch4mp
     */
    public static enum Csrf {
        DEFAULT, DISABLE, SESSION, COOKIE_HTTP_ONLY, COOKIE_ACCESSIBLE_FROM_JS
    }
}