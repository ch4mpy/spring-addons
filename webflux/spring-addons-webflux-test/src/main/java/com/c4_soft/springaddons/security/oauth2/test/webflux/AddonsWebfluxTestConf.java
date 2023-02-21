package com.c4_soft.springaddons.security.oauth2.test.webflux;

import static org.mockito.Mockito.mock;

import java.nio.charset.Charset;
import java.util.Arrays;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import reactor.core.publisher.Mono;

@TestConfiguration
@Import({ WebTestClientProperties.class })
public class AddonsWebfluxTestConf {

    @MockBean
    ReactiveJwtDecoder jwtDecoder;

    @MockBean
    JwtIssuerReactiveAuthenticationManagerResolver jwtIssuerReactiveAuthenticationManagerResolver;

    @MockBean
    ReactiveOpaqueTokenIntrospector introspector;

    @Bean
    HttpSecurity httpSecurity() {
        return mock(HttpSecurity.class);
    }

    @Bean
    @Scope("prototype")
    public WebTestClientSupport webTestClientSupport(
            WebTestClientProperties webTestClientProperties,
            WebTestClient webTestClient,
            SpringAddonsSecurityProperties addonsProperties) {
        return new WebTestClientSupport(webTestClientProperties, webTestClient, addonsProperties);
    }

    @ConditionalOnMissingBean
    @Bean
    OAuth2AuthoritiesConverter authoritiesConverter() {
        return mock(OAuth2AuthoritiesConverter.class);
    }

    @ConditionalOnMissingBean
    @Bean
    ServerAccessDeniedHandler serverAccessDeniedHandler() {
        return (var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
            var response = exchange.getResponse();
            response.setStatusCode(
                    principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
            response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
            var dataBufferFactory = response.bufferFactory();
            var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
            return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
        });
    }

    @ConditionalOnMissingBean
    @Bean
    SecurityWebFilterChain filterChain(
            ServerHttpSecurity http,
            ServerAccessDeniedHandler accessDeniedHandler,
            SpringAddonsSecurityProperties addonsProperties,
            ServerProperties serverProperties)
            throws Exception {

        if (addonsProperties.getPermitAll().length > 0) {
            http.anonymous();
        }

        if (addonsProperties.getCors().length > 0) {
            http.cors().configurationSource(corsConfigurationSource(addonsProperties));
        }

        final var configurer = http.csrf();
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
                configurer.csrfTokenRepository(new CookieServerCsrfTokenRepository());
                break;
            case COOKIE_ACCESSIBLE_FROM_JS:
                configurer.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse());
                break;
        }

        if (addonsProperties.isStatlessSessions()) {
            http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
        }

        if (!addonsProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
            http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
        }

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.redirectToHttps();
        }

        if (addonsProperties.isStatlessSessions()) {
            http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
        }

        if (!addonsProperties.isRedirectToLoginIfUnauthorizedOnRestrictedContent()) {
            http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);
        }

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.redirectToHttps();
        }

        http.authorizeExchange().pathMatchers(addonsProperties.getPermitAll()).permitAll();

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties addonsProperties) {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        for (final SpringAddonsSecurityProperties.CorsProperties corsProps : addonsProperties.getCors()) {
            final CorsConfiguration configuration = new CorsConfiguration();
            configuration.setAllowedOrigins(Arrays.asList(corsProps.getAllowedOrigins()));
            configuration.setAllowedMethods(Arrays.asList(corsProps.getAllowedMethods()));
            configuration.setAllowedHeaders(Arrays.asList(corsProps.getAllowedHeaders()));
            configuration.setExposedHeaders(Arrays.asList(corsProps.getExposedHeaders()));
            source.registerCorsConfiguration(corsProps.getPath(), configuration);
        }
        return source;
    }

}