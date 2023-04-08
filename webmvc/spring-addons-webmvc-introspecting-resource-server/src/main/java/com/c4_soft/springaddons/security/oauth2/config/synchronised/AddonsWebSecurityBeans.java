package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.CorsProperties;

import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * <b>Usage</b><br>
 * If not using spring-boot, &#64;Import or &#64;ComponentScan this class. All
 * beans defined here are &#64;ConditionalOnMissingBean =&gt;
 * just define your own &#64;Beans to override.
 * </p>
 * <p>
 * <b>Provided &#64;Beans</b>
 * </p>
 * <ul>
 * <li>springAddonsResourceServerSecurityFilterChain: applies CORS, CSRF,
 * anonymous, sessionCreationPolicy, SSL, redirect and 401 instead of redirect
 * to login as defined in <a href=
 * "https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-oauth2/src/main/java/com/c4_soft/springaddons/security/oauth2/config/SpringAddonsSecurityProperties.java">SpringAddonsSecurityProperties</a></li>
 * <li>authorizePostProcessor: a bean of type
 * {@link ResourceServerExpressionInterceptUrlRegistryPostProcessor} to fine
 * tune access
 * control from java configuration. It applies to all routes not listed in
 * "permit-all" property configuration. Default requires users to be
 * authenticated. <b>This is a bean to provide in your application configuration
 * if you prefer to define fine-grained access control rules with Java
 * configuration rather than methods security.</b></li>
 * <li>httpPostProcessor: a bean of type
 * {@link ResourceServerHttpSecurityPostProcessor} to
 * override anything from above auto-configuration. It is called just before the
 * security filter-chain is returned. Default is a no-op.</li>
 * <li>introspectionAuthenticationConverter: a converter from a successful
 * introspection to something inheriting from
 * {@link AbstractAuthenticationToken}. The default instantiate a
 * `BearerTokenAuthentication` with authorities mapping as configured for the
 * issuer declared in the introspected claims. The easiest to override the type
 * of {@link AbstractAuthenticationToken}, is to provide with an
 * {@link OAuth2AuthenticationFactory} bean.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnProperty(matchIfMissing = true, prefix = "com.c4-soft.springaddons.security", name = "enabled")
@AutoConfiguration
@EnableWebSecurity
@Slf4j
@Import({ AddonsSecurityBeans.class })
public class AddonsWebSecurityBeans {

    /**
     * <p>
     * Applies SpringAddonsSecurityProperties to web security config. Be aware that
     * defining a {@link SecurityWebFilterChain} bean with no security matcher and
     * an order higher than LOWEST_PRECEDENCE will disable most of this lib
     * auto-configuration for OpenID resource-servers.
     * </p>
     * <p>
     * You should consider to set security matcher to all other
     * {@link SecurityWebFilterChain} beans and provide
     * a {@link ServerHttpSecurityPostProcessor} bean to override anything from this
     * bean
     * </p>
     * .
     *
     * @param http                                 HTTP security to configure
     * @param serverProperties                     Spring "server" configuration
     *                                             properties
     * @param addonsProperties                     "com.c4-soft.springaddons.security"
     *                                             configuration properties
     * @param authorizePostProcessor               Hook to override access-control
     *                                             rules for all path that are not
     *                                             listed in "permit-all"
     * @param httpPostProcessor                    Hook to override all or part of
     *                                             HttpSecurity auto-configuration
     * @param introspectionAuthenticationConverter Converts successful introspection
     *                                             result into an
     *                                             {@link Authentication}
     * @return A default {@link SecurityWebFilterChain} for servlet resource-servers
     *         with access-token introspection (matches all unmatched routes with
     *         lowest precedence)
     */
    @Order(Ordered.LOWEST_PRECEDENCE)
    @Bean
    SecurityFilterChain springAddonsResourceServerSecurityFilterChain(
            HttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsSecurityProperties addonsProperties,
            ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
            ResourceServerHttpSecurityPostProcessor httpPostProcessor,
            OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter,
            OpaqueTokenIntrospector opaqueTokenIntrospector)
            throws Exception {
        http.oauth2ResourceServer(server -> server.opaqueToken(ot -> {
            ot.introspector(opaqueTokenIntrospector);
            ot.authenticationConverter(introspectionAuthenticationConverter);
        }));

        ServletConfigurationSupport.configureResourceServer(http, serverProperties, addonsProperties,
                authorizePostProcessor, httpPostProcessor);

        return http.build();
    }

    /**
     * Hook to override security rules for all path that are not listed in
     * "permit-all". Default is isAuthenticated().
     *
     * @return a hook to override security rules for all path that are not listed in
     *         "permit-all". Default is isAuthenticated().
     */
    @ConditionalOnMissingBean
    @Bean
    ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor() {
        return registry -> registry.anyRequest().authenticated();
    }

    /**
     * Hook to override all or part of HttpSecurity auto-configuration.
     * Called after spring-addons configuration was applied so that you can
     * modify anything
     *
     * @return a hook to override all or part of HttpSecurity auto-configuration.
     *         Called after spring-addons configuration was applied so that you can
     *         modify anything
     */
    @ConditionalOnMissingBean
    @Bean
    ResourceServerHttpSecurityPostProcessor httpPostProcessor() {
        return httpSecurity -> httpSecurity;
    }

    CorsConfigurationSource corsConfig(CorsProperties[] corsProperties) {
        log.debug("Building default CorsConfigurationSource with: {}", Stream.of(corsProperties).toList());
        final var source = new UrlBasedCorsConfigurationSource();
        for (final var corsProps : corsProperties) {
            final var configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
            configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
            configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
            configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
            source.registerCorsConfiguration(corsProps.getPath(), configuration);
        }
        return source;
    }

    /**
     * Converter bean from successful introspection result to an
     * {@link Authentication} instance
     *
     * @param authoritiesConverter  converts access-token claims into Spring
     *                              authorities
     * @param authenticationFactory builds an {@link Authentication} instance from
     *                              access-token string and claims
     * @return a converter from successful introspection result to an
     *         {@link Authentication} instance
     */
    @SuppressWarnings("unchecked")
    @ConditionalOnMissingBean
    @Bean
    OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
            Optional<OAuth2AuthenticationFactory> authenticationFactory,
            SpringAddonsSecurityProperties addonsProperties,
            OAuth2ResourceServerProperties resourceServerProperties) {
        return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> {
            return authenticationFactory
                    .map(af -> af.build(introspectedToken, authenticatedPrincipal.getAttributes())).orElse(
                            new BearerTokenAuthentication(
                                    new OAuth2IntrospectionAuthenticatedPrincipal(
                                            new OpenidClaimSet(authenticatedPrincipal.getAttributes(),
                                                    Stream.of(addonsProperties.getIssuers())
                                                            .filter(issProps -> resourceServerProperties
                                                                    .getOpaquetoken().getIntrospectionUri()
                                                                    .contains(issProps.getLocation().toString()))
                                                            .findAny().orElse(addonsProperties.getIssuers()[0])
                                                            .getUsernameClaim())
                                                    .getName(),
                                            authenticatedPrincipal.getAttributes(),
                                            (Collection<GrantedAuthority>) authenticatedPrincipal.getAuthorities()),
                                    new OAuth2AccessToken(
                                            OAuth2AccessToken.TokenType.BEARER,
                                            introspectedToken,
                                            authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT),
                                            authenticatedPrincipal
                                                    .getAttribute(OAuth2TokenIntrospectionClaimNames.EXP)),
                                    authoritiesConverter.convert(authenticatedPrincipal.getAttributes())));
        };
    }
}