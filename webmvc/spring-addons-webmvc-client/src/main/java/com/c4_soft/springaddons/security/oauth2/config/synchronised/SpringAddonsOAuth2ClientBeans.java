package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * The following {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBeans}
 * are auto-configured
 * <ul>
 * <li>springAddonsClientFilterChain: a {@link SecurityFilterChain}.
 * Instantiated only if
 * "com.c4-soft.springaddons.security.client.security-matchers" property has at
 * least one entry. If defined, it is with highest precedence, to ensure that
 * all routes defined in this security matcher property are intercepted by this
 * filter-chain.</li>
 * <li>oAuth2AuthorizationRequestResolver: a
 * {@link OAuth2AuthorizationRequestResolver}. Default instance is a
 * {@link SpringAddonsOAuth2AuthorizationRequestResolver} which sets the client
 * hostname in the redirect URI with
 * {@link SpringAddonsOAuth2ClientProperties#getClientUri()
 * SpringAddonsOAuth2ClientProperties#client-uri}</li>
 * <li>logoutRequestUriBuilder: builder for <a href=
 * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
 * Logout</a> queries, taking configuration from properties for OIDC providers
 * which do not strictly comply with the spec: logout URI not provided by OIDC
 * conf or non standard parameter names (Auth0 and Cognito are samples of such
 * OPs)</li>
 * <li>logoutSuccessHandler: a {@link LogoutSuccessHandler}. Default
 * instance is a {@link SpringAddonsOAuth2LogoutSuccessHandler} which logs a
 * user out from the last authorization server he logged on.</li>
 * <li>authoritiesConverter: an {@link OAuth2AuthoritiesConverter}. Default
 * instance is a {@link ConfigurableClaimSet2AuthoritiesConverter} which reads
 * spring-addons {@link SpringAddonsSecurityProperties}</li>
 * <li>grantedAuthoritiesMapper: a {@link GrantedAuthoritiesMapper} using the
 * already configured {@link OAuth2AuthoritiesConverter}</li>
 * <li>corsConfigurationSource: a {CorsConfigurationSource}. Default is built
 * from {@link SpringAddonsOAuth2ClientProperties}</li>
 * <li>oAuth2AuthorizedClientRepository: a
 * {@link SpringAddonsOAuth2AuthorizedClientRepository} (which is also a session
 * listener) capable of handling multi-tenancy and back-channel logout.</li>
 * <li>clientAuthorizePostProcessor: a
 * {@link ClientExpressionInterceptUrlRegistryPostProcessor} post processor to
 * fine tune access control from java configuration. It applies to all routes
 * not listed in "permit-all" property configuration. Default requires users to
 * be authenticated.</li>
 * <li>clientHttpPostProcessor: a
 * {@link ClientHttpSecurityPostProcessor} to override anything from above
 * auto-configuration. It is called just before the security filter-chain is
 * returned. Default is a no-op.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@EnableWebSecurity
@AutoConfiguration
@Import({ SpringAddonsOAuth2ClientProperties.class })
@Slf4j
public class SpringAddonsOAuth2ClientBeans {

    /**
     * <p>
     * Instantiated only if
     * "com.c4-soft.springaddons.security.client.security-matchers" property has at
     * least one entry. If defined, it is with highest precedence, to ensure that
     * all routes defined in this security matcher property are intercepted by this
     * filter-chain.
     * </p>
     * It defines:
     * <ul>
     * <li>the URI of a login page, which must be explicitly handled in a controller
     * with a static resource, a template (like in the resource server with UI
     * tutorial) or a redirection to an external app (as done in the BFF
     * tutorial)</li>
     * <li>logout (using {@link SpringAddonsOAuth2LogoutSuccessHandler} by
     * default)</li>
     * <li>forces SSL usage if it is enabled</li>
     * <li>CORS configuration as defined in spring-addons <b>client</b>
     * properties</li>
     * <li>CSRF protection as defined in spring-addons <b>client</b> properties
     * (enabled by default in this filter-chain).</li>
     * <li>allow access to unauthorized requests to path matchers listed in
     * spring-security <b>client</b> "permit-all" property</li>
     * <li>as usual, apply {@link ClientExpressionInterceptUrlRegistryPostProcessor}
     * for access control configuration from Java conf and
     * {@link ClientHttpSecurityPostProcessor} to override anything from the
     * auto-configuration listed above</li>
     * </ul>
     *
     * @param http                         the security filter-chain builder to
     *                                     configure
     * @param serverProperties             Spring Boot standard server properties
     * @param authorizationRequestResolver the authorization request resolver to
     *                                     use. By default
     *                                     {@link SpringAddonsOAuth2AuthorizationRequestResolver}
     * @param clientProps                  {@link SpringAddonsOAuth2ClientProperties
     *                                     spring-addons client properties}
     * @param authorizePostProcessor       post process authorization after
     *                                     "permit-all" configuration was applied
     *                                     (default is "isAuthenticated()" to
     *                                     everything that was not matched)
     * @param httpPostProcessor            post process the "http" builder just
     *                                     before it is returned (enables to
     *                                     override anything from the
     *                                     auto-configuration)
     * @param corsConfigurationSource      CORS configuration to apply. Default is
     *                                     built from
     *                                     {@link SpringAddonsOAuth2ClientProperties
     *                                     spring-addons client properties}
     * @return a security filter-chain scoped to specified security-matchers and
     *         adapted to OAuth2 clients
     * @throws Exception in case of miss-configuration
     */
    @ConditionalOnExpression("!(T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers:}') && T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers[0]:}'))")
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    @Bean
    SecurityFilterChain springAddonsClientFilterChain(
            HttpSecurity http,
            ServerProperties serverProperties,
            OAuth2AuthorizationRequestResolver authorizationRequestResolver,
            SpringAddonsOAuth2ClientProperties clientProps,
            ClientExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
            ClientHttpSecurityPostProcessor httpPostProcessor,
            CorsConfigurationSource corsConfigurationSource)
            throws Exception {
        // @formatter:off
        final var clientRoutes = Stream.of(clientProps.getSecurityMatchers()).map(AntPathRequestMatcher::new).toArray(AntPathRequestMatcher[]::new);
        log.info("Applying client OAuth2 configuration for: {}", Stream.of(clientRoutes).map(AntPathRequestMatcher::getPattern).toList());
        http.securityMatcher(new OrRequestMatcher(clientRoutes));

        authorizePostProcessor.authorizeHttpRequests(clientProps.getPermitAll().length == 0 ? http.authorizeHttpRequests()
                        : http.authorizeHttpRequests().requestMatchers(clientProps.getPermitAll()).permitAll());

        http.oauth2Login()
                .loginPage(UriComponentsBuilder.fromUri(clientProps.getClientUri()).path(clientProps.getLoginPath()).build().toString())
                .authorizationEndpoint().authorizationRequestResolver(authorizationRequestResolver).and()
                .defaultSuccessUrl(UriComponentsBuilder.fromUri(clientProps.getClientUri()).path(clientProps.getPostLoginRedirectPath()).build().toString(), true);

        http.logout();
        // @formatter:on

        // If SSL enabled, disable http (https only)
        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.requiresChannel().anyRequest().requiresSecure();
        }

        // configure CORS from application properties
        if (clientProps.getCors().length > 0) {
            http.cors().configurationSource(corsConfigurationSource);
        } else {
            http.cors().disable();
        }

        final var configurer = http.csrf();
        final var delegate = new XorCsrfTokenRequestAttributeHandler();
        delegate.setCsrfRequestAttributeName("_csrf");
        switch (clientProps.getCsrf()) {
            case DISABLE:
                configurer.disable();
                break;
            case DEFAULT:
            case SESSION:
                break;
            case COOKIE_HTTP_ONLY:
                // https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_a_single_page_application_with_cookiecsrftokenrepository
                configurer.csrfTokenRepository(new CookieCsrfTokenRepository())
                        .csrfTokenRequestHandler(delegate::handle);
                http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
                break;
            case COOKIE_ACCESSIBLE_FROM_JS:
                // https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_a_single_page_application_with_cookiecsrftokenrepository
                configurer.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(delegate::handle);
                http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
                break;
        }

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
     * Use a {@link SpringAddonsOAuth2AuthorizationRequestResolver} which takes
     * hostname and port from configuration properties (and works even if SSL is
     * enabled)
     *
     * @param clientRegistrationRepository
     * @param clientProps
     * @return {@link SpringAddonsOAuth2AuthorizationRequestResolver}
     */
    @ConditionalOnMissingBean
    @Bean
    OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            SpringAddonsOAuth2ClientProperties clientProps) {
        return new SpringAddonsOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
                clientProps.getClientUri());
    }

    /**
     * Build logout request for <a href=
     * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
     * Logout</a>. It works with most OIDC provider: those complying with the spec
     * (Keycloak for instance), off course, but also those which are close enough to
     * it (Auth0, Cognito, ...)
     *
     * @param clientProps {@link SpringAddonsOAuth2ClientProperties} to pick logout
     *                    configuration for divergence to the standard (logout URI
     *                    not provided in .well-known/openid-configuration and
     *                    non-conform parameter names)
     * @return {@link SpringAddonsOAuth2LogoutRequestUriBuilder]
     */
    @ConditionalOnMissingBean
    @Bean
    LogoutRequestUriBuilder logoutRequestUriBuilder(
            SpringAddonsOAuth2ClientProperties clientProps) {
        return new SpringAddonsOAuth2LogoutRequestUriBuilder(clientProps);
    }

    /**
     * Single tenant logout handler for OIDC provider complying to <a href=
     * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
     * Logout</a> (or approximately complying to it like Auth0 or Cognito)
     *
     * @param logoutRequestUriBuilder      delegate doing the smart job
     * @param clientRegistrationRepository
     * @return {@link SpringAddonsOAuth2LogoutSuccessHandler}
     */
    @ConditionalOnMissingBean
    @Bean
    LogoutSuccessHandler logoutSuccessHandler(LogoutRequestUriBuilder logoutRequestUriBuilder,
            ClientRegistrationRepository clientRegistrationRepository) {
        return new SpringAddonsOAuth2LogoutSuccessHandler(logoutRequestUriBuilder, clientRegistrationRepository);
    }

    /**
     * Instantiate a {@link ConfigurableClaimSet2AuthoritiesConverter} from token
     * claims to spring authorities (which claims to pick, how to transform roles
     * strings for each claim).
     *
     * @param addonsProperties converter configuration source
     * @return {@link ConfigurableClaimSet2AuthoritiesConverter}
     */
    @ConditionalOnMissingBean
    @Bean
    OAuth2AuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties addonsProperties) {
        return new ConfigurableClaimSet2AuthoritiesConverter(addonsProperties);
    }

    /**
     *
     * @param authoritiesConverter the authorities converter to use (by default
     *                             {@link ConfigurableClaimSet2AuthoritiesConverter})
     * @return {@link GrantedAuthoritiesMapper} using the authorities converter in
     *         the context
     */
    @ConditionalOnMissingBean
    @Bean
    GrantedAuthoritiesMapper grantedAuthoritiesMapper(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcAuth) {
                    mappedAuthorities.addAll(authoritiesConverter.convert(oidcAuth.getIdToken().getClaims()));

                } else if (authority instanceof OAuth2UserAuthority oauth2Auth) {
                    mappedAuthorities.addAll(authoritiesConverter.convert(oauth2Auth.getAttributes()));

                }
            });

            return mappedAuthorities;
        };
    }

    /**
     *
     * @param clientProperties the properties to pick CORS configuration from
     * @return a CORS configuration built from properties
     */
    @ConditionalOnMissingBean
    @Bean
    CorsConfigurationSource corsConfigurationSource(SpringAddonsOAuth2ClientProperties clientProperties) {
        final var source = new UrlBasedCorsConfigurationSource();
        for (final var corsProps : clientProperties.getCors()) {
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
     *
     * @param clientRegistrationRepository the OIDC providers configuration
     * @return {@link SpringAddonsOAuth2AuthorizedClientRepository}, an authorized
     *         client repository supporting multi-tenancy and exposing the required
     *         API for back-channel logout
     */
    @ConditionalOnMissingBean
    @Bean
    SpringAddonsOAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository(
            ClientRegistrationRepository clientRegistrationRepository) {
        return new SpringAddonsOAuth2AuthorizedClientRepository(clientRegistrationRepository);
    }

    /**
     * Post processor for access control in Java configuration.
     *
     * @author Jerome Wacongne ch4mp&#64;c4-soft.com
     *
     */
    public interface ClientExpressionInterceptUrlRegistryPostProcessor {
        AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorizeHttpRequests(
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry);
    }

    /**
     * @return a Post processor for access control in Java configuration which
     *         requires users to be authenticated. It is called after "permit-all"
     *         configuration property was applied.
     */
    @ConditionalOnMissingBean
    @Bean
    ClientExpressionInterceptUrlRegistryPostProcessor clientAuthorizePostProcessor() {
        return registry -> registry.anyRequest().authenticated();
    }

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

    /**
     *
     * @return a no-op post processor
     */
    @ConditionalOnMissingBean
    @Bean
    ClientHttpSecurityPostProcessor clientHttpPostProcessor() {
        return http -> http;
    }

    static class HasClientSecurityMatcher extends AnyNestedCondition {

        public HasClientSecurityMatcher() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @ConditionalOnExpression("!(T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers:}') && T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers[0]:}'))")
        static class Value1Condition {

        }

        @ConditionalOnProperty(name = "com.c4-soft.springaddons.security.client.security-matchers[0]")
        static class Value2Condition {

        }

    }
}