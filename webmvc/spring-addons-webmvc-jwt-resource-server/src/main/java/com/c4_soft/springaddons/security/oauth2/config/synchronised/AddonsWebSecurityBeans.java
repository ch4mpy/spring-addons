package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.c4_soft.springaddons.security.oauth2.OpenidClaimSet;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

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
 * <li>corsConfigurationSource: fine grained CORS from configuration properties,
 * per path matcher</li>
 * <li>jwtAuthenticationConverter: a converter from a {@link Jwt} to something
 * inheriting from {@link AbstractAuthenticationToken}. The default instantiate
 * a {@link JwtAuthenticationToken} with username and authorities as configured
 * for the issuer of thi token. The easiest to override the type of
 * {@link AbstractAuthenticationToken}, is to provide with an
 * {@link OAuth2AuthenticationFactory} bean.</li>
 * <li>authenticationManagerResolver: to accept authorities from more than one
 * issuer, the recommended way is to provide an
 * {@link JwtIssuerAuthenticationManagerResolver} supporting it. Default keeps a
 * {@link JwtAuthenticationProvider} with its own {@link JwtDecoder} for each
 * issuer.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@AutoConfiguration
@EnableWebSecurity
@Slf4j
@Import({ AddonsSecurityBeans.class })
public class AddonsWebSecurityBeans {
    /**
     * <p>
     * Applies SpringAddonsSecurityProperties to web security config. Be aware that
     * defining a {@link SecurityWebFilterChain} bean with no
     * security matcher and an order higher than LOWEST_PRECEDENCE will disable most
     * of this lib auto-configuration for OpenID resource-servers.
     * </p>
     * <p>
     * You should consider to set security matcher to all other
     * {@link SecurityWebFilterChain} beans and provide a
     * {@link ServerHttpSecurityPostProcessor} bean to override anything from this
     * bean
     * </p>
     * .
     *
     * @param http                          HTTP security to configure
     * @param serverProperties              Spring "server" configuration properties
     * @param addonsProperties              "com.c4-soft.springaddons.security"
     *                                      configuration properties
     * @param authorizePostProcessor        Hook to override access-control rules
     *                                      for all path that are not listed in
     *                                      "permit-all"
     * @param httpPostProcessor             Hook to override all or part of
     *                                      HttpSecurity auto-configuration
     * @param authenticationManagerResolver Converts successful JWT decoding result
     *                                      into an {@link Authentication}
     * @param corsConfigurationSource
     * @return A default {@link SecurityWebFilterChain} for servlet resource-servers
     *         with JWT decoder (matches all
     *         unmatched routes with lowest precedence)
     */
    @Order(Ordered.LOWEST_PRECEDENCE)
    @Bean
    SecurityFilterChain springAddonsResourceServerSecurityFilterChain(
            HttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsSecurityProperties addonsProperties,
            ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
            HttpSecurityPostProcessor httpPostProcessor,
            AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
            CorsConfigurationSource corsConfigurationSource)
            throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));

        if (addonsProperties.getPermitAll().length > 0) {
            http.anonymous();
        }

        if (addonsProperties.getCors().length > 0) {
            http.cors().configurationSource(corsConfigurationSource);
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
     * hook to override security rules for all path that are not listed in
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
     * Hook to override all or part of HttpSecurity auto-configuration. Called after
     * spring-addons configuration was applied so that you can
     * modify anything
     *
     * @return a hook to override all or part of HttpSecurity auto-configuration.
     *         Called after spring-addons configuration was applied so that
     *         you can modify anything
     */
    @ConditionalOnMissingBean
    @Bean
    HttpSecurityPostProcessor httpPostProcessor() {
        return httpSecurity -> httpSecurity;
    }

    @ConditionalOnMissingBean
    @Bean
    CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties addonsProperties) {
        log.debug("Building default CorsConfigurationSource with: {}", Stream.of(addonsProperties.getCors()).toList());
        final var source = new UrlBasedCorsConfigurationSource();
        for (final var corsProps : addonsProperties.getCors()) {
            final var configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
            configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
            configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
            configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
            source.registerCorsConfiguration(corsProps.getPath(), configuration);
        }
        return source;
    }

    public static interface Jwt2AuthenticationConverter<T extends AbstractAuthenticationToken>
            extends Converter<Jwt, T> {
    }

    /**
     * Converter bean from {@link Jwt} to {@link AbstractAuthenticationToken}
     *
     * @param authoritiesConverter  converts access-token claims into Spring
     *                              authorities
     * @param securityProperties    Spring "spring.security" configuration
     *                              properties
     * @param authenticationFactory builds an {@link Authentication} instance from
     *                              access-token string and claims
     * @return a converter from {@link Jwt} to {@link AbstractAuthenticationToken}
     */
    @ConditionalOnMissingBean
    @Bean
    Jwt2AuthenticationConverter<? extends AbstractAuthenticationToken> jwtAuthenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
            SpringAddonsSecurityProperties addonsProperties,
            Optional<OAuth2AuthenticationFactory> authenticationFactory) {
        return jwt -> authenticationFactory.map(af -> af.build(jwt.getTokenValue(), jwt.getClaims())).orElse(
                new JwtAuthenticationToken(
                        jwt,
                        authoritiesConverter.convert(jwt.getClaims()),
                        new OpenidClaimSet(jwt.getClaims(),
                                addonsProperties.getIssuerProperties(jwt.getIssuer()).getUsernameClaim()).getName()));
    }

    /**
     * Provides with multi-tenancy: builds a JwtIssuerAuthenticationManagerResolver
     * per provided OIDC issuer URI
     *
     * @param auth2ResourceServerProperties "spring.security.oauth2.resourceserver"
     *                                      configuration properties
     * @param addonsProperties              "com.c4-soft.springaddons.security"
     *                                      configuration properties
     * @param jwtAuthenticationConverter    converts from a {@link Jwt} to an
     *                                      {@link Authentication} implementation
     * @return Multi-tenant {@link JwtIssuerAuthenticationManagerResolver} (one for
     *         each configured issuer)
     */
    @ConditionalOnMissingBean
    @Bean
    JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(
            OAuth2ResourceServerProperties auth2ResourceServerProperties,
            SpringAddonsSecurityProperties addonsProperties,
            Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
        final var jwtProps = Optional.ofNullable(auth2ResourceServerProperties)
                .map(OAuth2ResourceServerProperties::getJwt);
        // @formatter:off
		Optional.ofNullable(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getIssuerUri)).orElse(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getJwkSetUri))
		    .filter(StringUtils::hasLength)
		    .ifPresent(jwtConf -> {
				log.warn("spring.security.oauth2.resourceserver configuration will be ignored in favor of com.c4-soft.springaddons.security");
			});
		// @formatter:on

        final Map<String, AuthenticationManager> jwtManagers = Stream.of(addonsProperties.getIssuers())
                .collect(Collectors.toMap(issuer -> issuer.getLocation().toString(), issuer -> {
                    JwtDecoder decoder = issuer.getJwkSetUri() != null
                            && StringUtils.hasLength(issuer.getJwkSetUri().toString())
                                    ? NimbusJwtDecoder.withJwkSetUri(issuer.getJwkSetUri().toString()).build()
                                    : JwtDecoders.fromIssuerLocation(issuer.getLocation().toString());
                    var provider = new JwtAuthenticationProvider(decoder);
                    provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
                    return provider::authenticate;
                }));

        log.debug(
                "Building default JwtIssuerAuthenticationManagerResolver with: ",
                auth2ResourceServerProperties.getJwt(),
                Stream.of(addonsProperties.getIssuers()).toList());

        return new JwtIssuerAuthenticationManagerResolver((AuthenticationManagerResolver<String>) jwtManagers::get);
    }
}