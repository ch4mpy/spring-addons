package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.CorsProperties;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
 * {@link ExpressionInterceptUrlRegistryPostProcessor} to fine tune access
 * control from java configuration. It applies to all routes not listed in
 * "permit-all" property configuration. Default requires users to be
 * authenticated. <b>This is a bean to provide in your application configuration
 * if you prefer to define fine-grained access control rules with Java
 * configuration rather than methods security.</b></li>
 * <li>httpPostProcessor: a bean of type {@link HttpSecurityPostProcessor} to
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
            ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
            HttpSecurityPostProcessor httpPostProcessor,
            OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter)
            throws Exception {
        http.oauth2ResourceServer().opaqueToken().authenticationConverter(introspectionAuthenticationConverter);

        if (addonsProperties.getPermitAll().length > 0) {
            http.anonymous();
        }

        if (addonsProperties.getCors().length > 0) {
            http.cors().configurationSource(corsConfig(addonsProperties.getCors()));
        } else {
            http.cors().disable();
        }

        final var configurer = http.csrf();
        final var delegate = new XorCsrfTokenRequestAttributeHandler();
        delegate.setCsrfRequestAttributeName("_csrf");
        switch (addonsProperties.getCsrf()) {
            case DISABLE:
                configurer.disable();
                break;
            case DEFAULT:
                if (addonsProperties.isStatlessSessions()) {
                    configurer.disable();
                }
                break;
            case SESSION:
                break;
            case COOKIE_HTTP_ONLY:
                configurer.csrfTokenRepository(new CookieCsrfTokenRepository())
                        .csrfTokenRequestHandler(delegate::handle);
                http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
                break;
            case COOKIE_ACCESSIBLE_FROM_JS:
                // Adapted from
                // https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_angularjs_or_another_javascript_framework
                configurer.csrfTokenRepository(new CookieCsrfTokenRepository())
                        .csrfTokenRequestHandler(delegate::handle);
                http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
                break;
        }

        if (addonsProperties.isStatlessSessions()) {
            http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }

        if (!addonsProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
            http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
                response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
                response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
            });
        }

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.requiresChannel().anyRequest().requiresSecure();
        }

        authorizePostProcessor
                .authorizeHttpRequests(addonsProperties.getPermitAll().length == 0 ? http.authorizeHttpRequests()
                        : http.authorizeHttpRequests().requestMatchers(addonsProperties.getPermitAll()).permitAll());

        return httpPostProcessor.process(http).build();
    }

    /**
     * https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_a_single_page_application_with_cookiecsrftokenrepository
     *
     */
    private static final class CsrfCookieFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                FilterChain filterChain)
                throws ServletException, IOException {
            CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
            // Render the token value to a cookie by causing the deferred token to be loaded
            csrfToken.getToken();

            filterChain.doFilter(request, response);
        }

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
    ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor() {
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
    HttpSecurityPostProcessor httpPostProcessor() {
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
    @ConditionalOnMissingBean
    @Bean
    OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
            Optional<OAuth2AuthenticationFactory> authenticationFactory) {
        return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> authenticationFactory
                .map(af -> af.build(introspectedToken, authenticatedPrincipal.getAttributes())).orElse(
                        new BearerTokenAuthentication(
                                authenticatedPrincipal,
                                new OAuth2AccessToken(
                                        OAuth2AccessToken.TokenType.BEARER,
                                        introspectedToken,
                                        authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT),
                                        authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP)),
                                authoritiesConverter.convert(authenticatedPrincipal.getAttributes())));
    }
}