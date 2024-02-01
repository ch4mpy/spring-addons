package com.c4_soft.springaddons.security.oidc.starter.reactive;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.List;
import java.util.Optional;

import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.c4_soft.springaddons.security.oidc.starter.properties.CorsProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.Csrf;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcResourceServerProperties;
import com.c4_soft.springaddons.security.oidc.starter.reactive.client.ClientAuthorizeExchangeSpecPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.reactive.client.ClientHttpSecurityPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ResourceServerAuthorizeExchangeSpecPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ResourceServerHttpSecurityPostProcessor;

import reactor.core.publisher.Mono;

public class ReactiveConfigurationSupport {

    public static ServerHttpSecurity configureResourceServer(
            ServerHttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsOidcResourceServerProperties addonsResourceServerProperties,
            ServerAuthenticationEntryPoint authenticationEntryPoint,
            Optional<ServerAccessDeniedHandler> accessDeniedHandler,
            ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
            ResourceServerHttpSecurityPostProcessor httpPostProcessor) {

        ReactiveConfigurationSupport.configureCors(http, addonsResourceServerProperties.getCors());
        ReactiveConfigurationSupport.configureState(http, addonsResourceServerProperties.isStatlessSessions(), addonsResourceServerProperties.getCsrf());
        ReactiveConfigurationSupport.configureAccess(http, addonsResourceServerProperties.getPermitAll());

        http.exceptionHandling(handling -> {
            handling.authenticationEntryPoint(authenticationEntryPoint);
            accessDeniedHandler.ifPresent(handling::accessDeniedHandler);
        });

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.redirectToHttps(withDefaults());
        }

        http.authorizeExchange(registry -> authorizePostProcessor.authorizeHttpRequests(registry));
        httpPostProcessor.process(http);

        return http;
    }

    public static ServerHttpSecurity configureClient(
            ServerHttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsOidcClientProperties addonsClientProperties,
            ClientAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
            ClientHttpSecurityPostProcessor httpPostProcessor) {

        ReactiveConfigurationSupport.configureCors(http, addonsClientProperties.getCors());
        ReactiveConfigurationSupport.configureState(http, false, addonsClientProperties.getCsrf());
        ReactiveConfigurationSupport.configureAccess(http, addonsClientProperties.getPermitAll());

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.redirectToHttps(withDefaults());
        }

        http.authorizeExchange(registry -> authorizePostProcessor.authorizeHttpRequests(registry));
        httpPostProcessor.process(http);

        return http;
    }

    public static ServerHttpSecurity configureAccess(ServerHttpSecurity http, List<String> permitAll) {
        if (permitAll.size() > 0) {
            http.anonymous(withDefaults());
            http.authorizeExchange(authorizeExchange -> authorizeExchange.pathMatchers(permitAll.toArray(new String[] {})).permitAll());
        }
        return http;
    }

    public static ServerHttpSecurity configureCors(ServerHttpSecurity http, List<CorsProperties> corsProperties) {
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

    public static ServerHttpSecurity configureState(ServerHttpSecurity http, boolean isStatless, Csrf csrfEnum) {

        if (isStatless) {
            http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
        }

        http.csrf(csrf -> {
            switch (csrfEnum) {
                case DISABLE:
                    csrf.disable();
                    break;
                case DEFAULT:
                    if (isStatless) {
                        csrf.disable();
                    } else {
                        withDefaults();
                    }
                    break;
                case SESSION:
                    withDefaults();
                    break;
                case COOKIE_ACCESSIBLE_FROM_JS:
                    // adapted from https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa
                    csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()).csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler());
                    break;
            }
        });

        return http;
    }

    /**
     * Adapted from https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa
     */
    static final class SpaCsrfTokenRequestHandler extends ServerCsrfTokenRequestAttributeHandler {
        private final ServerCsrfTokenRequestAttributeHandler delegate = new XorServerCsrfTokenRequestAttributeHandler();

        @Override
        public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken) {
            /*
             * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of the CsrfToken when it is rendered in the response body.
             */
            this.delegate.handle(exchange, csrfToken);
        }

        @Override
        public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
            final var hasHeader = exchange.getRequest().getHeaders().get(csrfToken.getHeaderName()).stream().filter(StringUtils::hasText).count() > 0;
            return hasHeader ? super.resolveCsrfTokenValue(exchange, csrfToken) : this.delegate.resolveCsrfTokenValue(exchange, csrfToken);
        }
    }
}
