package com.c4_soft.springaddons.security.oidc.starter.synchronised;

import static org.springframework.security.config.Customizer.withDefaults;

import java.io.IOException;
import java.util.List;
import java.util.function.Supplier;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.lang.NonNull;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.c4_soft.springaddons.security.oidc.starter.properties.CorsProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.Csrf;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcResourceServerProperties;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.client.ClientExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.client.ClientSynchronizedHttpSecurityPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerSynchronizedHttpSecurityPostProcessor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ServletConfigurationSupport {

    public static HttpSecurity configureResourceServer(
            HttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsOidcResourceServerProperties addonsResourceServerProperties,
            ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
            ResourceServerSynchronizedHttpSecurityPostProcessor httpPostProcessor)
            throws Exception {

        ServletConfigurationSupport.configureCors(http, addonsResourceServerProperties.getCors());
        ServletConfigurationSupport.configureState(http, addonsResourceServerProperties.isStatlessSessions(), addonsResourceServerProperties.getCsrf());
        ServletConfigurationSupport
            .configureAccess(http, addonsResourceServerProperties.getPermitAll(), addonsResourceServerProperties.getCors(), authorizePostProcessor);

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
        }

        return httpPostProcessor.process(http);
    }

    public static HttpSecurity configureClient(
            HttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsOidcClientProperties addonsClientProperties,
            ClientExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
            ClientSynchronizedHttpSecurityPostProcessor httpPostProcessor)
            throws Exception {

        ServletConfigurationSupport.configureCors(http, addonsClientProperties.getCors());
        ServletConfigurationSupport.configureState(http, false, addonsClientProperties.getCsrf());
        ServletConfigurationSupport.configureAccess(http, addonsClientProperties.getPermitAll(), addonsClientProperties.getCors(), authorizePostProcessor);

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
        }

        return httpPostProcessor.process(http);
    }

    public static HttpSecurity configureAccess(
            HttpSecurity http,
            List<String> permitAll,
            List<CorsProperties> corsProperties,
            ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor)
            throws Exception {
        final var permittedCorsOptions = corsProperties
            .stream()
            .filter(cors -> (cors.getAllowedMethods().contains("*") || cors.getAllowedMethods().contains("OPTIONS")) && !cors.isDisableAnonymousOptions())
            .map(CorsProperties::getPath)
            .toList();

        if (permitAll.size() > 0 || permittedCorsOptions.size() > 0) {
            http.anonymous(withDefaults());
        }

        if (permitAll.size() > 0) {
            http
                .authorizeHttpRequests(
                    registry -> registry.requestMatchers(permitAll.stream().map(AntPathRequestMatcher::new).toArray(AntPathRequestMatcher[]::new)).permitAll());
        }

        if (permittedCorsOptions.size() > 0) {
            http
                .authorizeHttpRequests(
                    registry -> registry
                        .requestMatchers(
                            permittedCorsOptions
                                .stream()
                                .map(corsPathPattern -> new AntPathRequestMatcher(corsPathPattern, "OPTIONS"))
                                .toArray(AntPathRequestMatcher[]::new))
                        .permitAll());
        }

        return http.authorizeHttpRequests(registry -> authorizePostProcessor.authorizeHttpRequests(registry));
    }

    public static HttpSecurity configureCors(HttpSecurity http, List<CorsProperties> corsProperties) throws Exception {
        if (corsProperties.size() == 0) {
            http.cors(cors -> cors.disable());
        } else {
            final var source = new UrlBasedCorsConfigurationSource();
            for (final var corsProps : corsProperties) {
                final var configuration = new CorsConfiguration();
                configuration.setAllowCredentials(corsProps.getAllowCredentials());
                configuration.setAllowedHeaders(corsProps.getAllowedHeaders());
                configuration.setAllowedMethods(corsProps.getAllowedMethods());
                configuration.setAllowedOriginPatterns(corsProps.getAllowedOriginPatterns());
                configuration.setExposedHeaders(corsProps.getExposedHeaders());
                configuration.setMaxAge(corsProps.getMaxAge());
                source.registerCorsConfiguration(corsProps.getPath(), configuration);
            }
            http.cors(cors -> cors.configurationSource(source));
        }
        return http;
    }

    public static HttpSecurity configureState(HttpSecurity http, boolean isStatless, Csrf csrfEnum) throws Exception {

        if (isStatless) {
            http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        }

        http.csrf(configurer -> {
            switch (csrfEnum) {
                case DISABLE:
                    configurer.disable();
                    break;
                case DEFAULT:
                    if (isStatless) {
                        configurer.disable();
                    }
                    break;
                case SESSION:
                    break;
                case COOKIE_ACCESSIBLE_FROM_JS:
                    // Taken from
                    // https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa-configuration
                    configurer.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler());
                    http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
                    break;
            }
        });

        return http;
    }

    /**
     * Copied from https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa-configuration
     */
    static final class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {
        private final CsrfTokenRequestHandler delegate = new XorCsrfTokenRequestAttributeHandler();

        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
            /*
             * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of the CsrfToken when it is rendered in the response body.
             */
            this.delegate.handle(request, response, csrfToken);
        }

        @Override
        public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
            /*
             * If the request contains a request header, use CsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies when a single-page
             * application includes the header value automatically, which was obtained via a cookie containing the raw CsrfToken.
             */
            final var csrfHeader = request.getHeader(csrfToken.getHeaderName());
            if (StringUtils.hasText(csrfHeader)) {
                return csrfHeader;
            }
            /*
             * In all other cases (e.g. if the request contains a request parameter), use XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This
             * applies when a server-side rendered form includes the _csrf request parameter as a hidden input.
             */
            return this.delegate.resolveCsrfTokenValue(request, csrfToken);
        }
    }

    /**
     * Copied from https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa-configuration
     */
    static final class CsrfCookieFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
                throws ServletException,
                    IOException {
            CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
            // Render the token value to a cookie by causing the deferred token to be loaded
            csrfToken.getToken();

            filterChain.doFilter(request, response);
        }
    }
}
