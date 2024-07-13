package com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver;

import java.nio.charset.Charset;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;

import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.CookieCsrfCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationManagerResolverCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultCorsWebFilterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultJwtAbstractAuthenticationTokenConverterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOpaqueTokenAuthenticationConverterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.IsIntrospectingResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.IsJwtDecoderResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsNotServlet;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveConfigurationSupport;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveSpringAddonsOidcBeans;

import reactor.core.publisher.Mono;

/**
 * <p>
 * <b>Usage</b><br>
 * If not using spring-boot, &#64;Import or &#64;ComponentScan this class. All beans defined here are &#64;ConditionalOnMissingBean =&gt; just define your own
 * &#64;Beans to override.
 * </p>
 * <p>
 * <b>Provided &#64;Beans</b>
 * </p>
 * <ul>
 * <li><b>SecurityWebFilterChain</b>: applies CORS, CSRF, anonymous, sessionCreationPolicy, SSL redirect and 401 instead of redirect to login properties as
 * defined in {@link SpringAddonsOidcProperties}</li>
 * <li><b>AuthorizeExchangeSpecPostProcessor</b>. Override if you need fined grained HTTP security (more than authenticated() to all routes but the ones defined
 * as permitAll() in {@link SpringAddonsOidcProperties}</li>
 * <li><b>Jwt2AuthoritiesConverter</b>: responsible for converting the JWT into Collection&lt;? extends GrantedAuthority&gt;</li>
 * <li><b>ReactiveJwt2OpenidClaimSetConverter&lt;T extends Map&lt;String, Object&gt; &amp; Serializable&gt;</b>: responsible for converting the JWT into a
 * claim-set of your choice (OpenID or not)</li>
 * <li><b>ReactiveJwt2AuthenticationConverter&lt;OAuthentication&lt;T extends OpenidClaimSet&gt;&gt;</b>: responsible for converting the JWT into an
 * Authentication (uses both beans above)</li>
 * <li><b>ReactiveAuthenticationManagerResolver</b>: required to be able to define more than one token issuer until
 * https://github.com/spring-projects/spring-boot/issues/30108 is solved</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Conditional({ IsOidcResourceServerCondition.class, IsNotServlet.class })
@EnableWebFluxSecurity
@AutoConfiguration
@ImportAutoConfiguration(ReactiveSpringAddonsOidcBeans.class)
public class ReactiveSpringAddonsOidcResourceServerBeans {

    /**
     * <p>
     * Applies SpringAddonsSecurityProperties to web security config. Be aware that defining a {@link SecurityWebFilterChain} bean with no security matcher and
     * an order higher than LOWEST_PRECEDENCE will disable most of this lib auto-configuration for OpenID resource-servers.
     * </p>
     * <p>
     * You should consider to set security matcher to all other {@link SecurityWebFilterChain} beans and provide a
     * {@link ResourceServerReactiveHttpSecurityPostProcessor} bean to override anything from this bean
     * </p>
     * .
     *
     * @param http HTTP security to configure
     * @param serverProperties Spring "server" configuration properties
     * @param addonsProperties "com.c4-soft.springaddons.oidc" configuration properties
     * @param authorizePostProcessor Hook to override access-control rules for all path that are not listed in "permit-all"
     * @param httpPostProcessor Hook to override all or part of HttpSecurity auto-configuration
     * @param authenticationManagerResolver Converts successful JWT decoding result into an {@link Authentication}
     * @param authenticationEntryPoint The {@link AuthenticationEntryPoint} to use (defaults returns 401)
     * @param accessDeniedHandler An optional {@link AccessDeniedHandler} to use instead of Boot default one
     * @return A default {@link SecurityWebFilterChain} for reactive resource-servers with JWT decoder(matches all unmatched routes with lowest precedence)
     */
    @Conditional(IsJwtDecoderResourceServerCondition.class)
    @Order(Ordered.LOWEST_PRECEDENCE)
    @Bean
    SecurityWebFilterChain springAddonsJwtResourceServerSecurityFilterChain(
            ServerHttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsOidcProperties addonsProperties,
            ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
            ResourceServerReactiveHttpSecurityPostProcessor httpPostProcessor,
            ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver,
            ServerAuthenticationEntryPoint authenticationEntryPoint,
            Optional<ServerAccessDeniedHandler> accessDeniedHandler) {
        http.oauth2ResourceServer(server -> server.authenticationManagerResolver(authenticationManagerResolver));

        ReactiveConfigurationSupport
            .configureResourceServer(
                http,
                serverProperties,
                addonsProperties,
                authenticationEntryPoint,
                accessDeniedHandler,
                authorizePostProcessor,
                httpPostProcessor);

        return http.build();
    }

    /**
     * <p>
     * Applies SpringAddonsSecurityProperties to web security config. Be aware that defining a {@link SecurityWebFilterChain} bean with no security matcher and
     * an order higher than LOWEST_PRECEDENCE will disable most of this lib auto-configuration for OpenID resource-servers.
     * </p>
     * <p>
     * You should consider to set security matcher to all other {@link SecurityWebFilterChain} beans and provide a
     * {@link ResourceServerReactiveHttpSecurityPostProcessor} bean to override anything from this bean
     * </p>
     * .
     *
     * @param http HTTP security to configure
     * @param serverProperties Spring "server" configuration properties
     * @param addonsProperties "com.c4-soft.springaddons.oidc" configuration properties
     * @param authorizePostProcessor Hook to override access-control rules for all path that are not listed in "permit-all"
     * @param httpPostProcessor Hook to override all or part of HttpSecurity auto-configuration
     * @param introspectionAuthenticationConverter Converts successful introspection result into an {@link Authentication}
     * @param authenticationEntryPoint The {@link AuthenticationEntryPoint} to use (defaults returns 401)
     * @param accessDeniedHandler An optional {@link AccessDeniedHandler} to use instead of Boot default one
     * @return A default {@link SecurityWebFilterChain} for reactive resource-servers with access-token introspection (matches all unmatched routes with lowest
     *         precedence)
     */
    @Conditional(IsIntrospectingResourceServerCondition.class)
    @Order(Ordered.LOWEST_PRECEDENCE)
    @Bean
    SecurityWebFilterChain springAddonsIntrospectingResourceServerSecurityFilterChain(
            ServerHttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsOidcProperties addonsProperties,
            ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
            ResourceServerReactiveHttpSecurityPostProcessor httpPostProcessor,
            ReactiveOpaqueTokenAuthenticationConverter introspectionAuthenticationConverter,
            ReactiveOpaqueTokenIntrospector opaqueTokenIntrospector,
            ServerAuthenticationEntryPoint authenticationEntryPoint,
            Optional<ServerAccessDeniedHandler> accessDeniedHandler) {
        http.oauth2ResourceServer(server -> server.opaqueToken(ot -> {
            ot.introspector(opaqueTokenIntrospector);
            ot.authenticationConverter(introspectionAuthenticationConverter);
        }));

        ReactiveConfigurationSupport
            .configureResourceServer(
                http,
                serverProperties,
                addonsProperties,
                authenticationEntryPoint,
                accessDeniedHandler,
                authorizePostProcessor,
                httpPostProcessor);

        return http.build();
    }

    /**
     * Hook to override security rules for all path that are not listed in "permit-all". Default is isAuthenticated().
     *
     * @return a hook to override security rules for all path that are not listed in "permit-all". Default is isAuthenticated().
     */
    @ConditionalOnMissingBean
    @Bean
    ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor() {
        return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec.anyExchange().authenticated();
    }

    /**
     * Hook to override all or part of HttpSecurity auto-configuration. Called after spring-addons configuration was applied so that you can modify anything
     *
     * @return a hook to override all or part of HttpSecurity auto-configuration. Called after spring-addons configuration was applied so that you can modify
     *         anything
     */
    @ConditionalOnMissingBean
    @Bean
    ResourceServerReactiveHttpSecurityPostProcessor httpPostProcessor() {
        return serverHttpSecurity -> serverHttpSecurity;
    }

    @ConditionalOnMissingBean
    @Bean
    SpringAddonsReactiveJwtDecoderFactory springAddonsJwtDecoderFactory() {
        return new DefaultSpringAddonsReactiveJwtDecoderFactory();
    }

    /**
     * Provides with multi-tenancy: builds a ReactiveAuthenticationManagerResolver per provided OIDC issuer URI
     *
     * @param auth2ResourceServerProperties "spring.security.oauth2.resourceserver" configuration properties
     * @param addonsProperties "com.c4-soft.springaddons.oidc" configuration properties
     * @param jwtAuthenticationConverter converts from a {@link Jwt} to an {@link Authentication} implementation
     * @return Multi-tenant {@link ReactiveAuthenticationManagerResolver} (one for each configured issuer)
     */
    @Conditional(DefaultAuthenticationManagerResolverCondition.class)
    @Bean
    ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver(
            OpenidProviderPropertiesResolver opPropertiesResolver,
            SpringAddonsReactiveJwtDecoderFactory jwtDecoderFactory,
            Converter<Jwt, ? extends Mono<? extends AbstractAuthenticationToken>> jwtAuthenticationConverter) {
        return new SpringAddonsReactiveJwtAuthenticationManagerResolver(opPropertiesResolver, jwtDecoderFactory, jwtAuthenticationConverter);
    }

    /**
     * Bean to switch from default behavior of redirecting unauthorized users to login (302) to returning 401 (unauthorized)
     *
     * @return a bean to switch from default behavior of redirecting unauthorized users to login (302) to returning 401 (unauthorized)
     */
    @ConditionalOnMissingBean
    @Bean
    ServerAuthenticationEntryPoint authenticationEntryPoint() {
        return (ServerWebExchange exchange, AuthenticationException ex) -> exchange.getPrincipal().flatMap(principal -> {
            var response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"Restricted Content\"");
            var dataBufferFactory = response.bufferFactory();
            var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
            return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
        });
    }

    /**
     * https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework
     */
    @Conditional(CookieCsrfCondition.class)
    @ConditionalOnMissingBean(name = "csrfCookieWebFilter")
    @Bean
    WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
            return csrfToken.doOnSuccess(token -> {}).then(chain.filter(exchange));
        };
    }

    /**
     * Converter bean from {@link Jwt} to {@link AbstractAuthenticationToken}
     *
     * @param authoritiesConverter converts access-token claims into Spring authorities
     * @param authenticationFactory builds an {@link Authentication} instance from access-token string and claims
     * @return a converter from {@link Jwt} to {@link AbstractAuthenticationToken}
     */
    @Conditional(DefaultJwtAbstractAuthenticationTokenConverterCondition.class)
    @Bean
    ReactiveJwtAbstractAuthenticationTokenConverter jwtAuthenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
            OpenidProviderPropertiesResolver opPropertiesResolver) {
        return jwt -> Mono
            .just(
                new JwtAuthenticationToken(
                    jwt,
                    authoritiesConverter.convert(jwt.getClaims()),
                    new OpenidClaimSet(
                        jwt.getClaims(),
                        opPropertiesResolver
                            .resolve(jwt.getClaims())
                            .orElseThrow(() -> new NotAConfiguredOpenidProviderException(jwt.getClaims()))
                            .getUsernameClaim()).getName()));
    }

    /**
     * Converter bean from successful introspection result to {@link Authentication} instance
     *
     * @param authoritiesConverter converts access-token claims into Spring authorities
     * @param authenticationFactory builds an {@link Authentication} instance from access-token string and claims
     * @return a converter from successful introspection result to {@link Authentication} instance
     */
    @Conditional(DefaultOpaqueTokenAuthenticationConverterCondition.class)
    @Bean
    @SuppressWarnings("unchecked")
    ReactiveOpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
            SpringAddonsOidcProperties addonsProperties,
            OAuth2ResourceServerProperties resourceServerProperties) {
        return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> Mono
            .just(
                new BearerTokenAuthentication(
                    new OAuth2IntrospectionAuthenticatedPrincipal(
                        new OpenidClaimSet(
                            authenticatedPrincipal.getAttributes(),
                            addonsProperties
                                .getOps()
                                .stream()
                                .filter(issProps -> resourceServerProperties.getOpaquetoken().getIntrospectionUri().contains(issProps.getIss().toString()))
                                .findAny()
                                .orElse(addonsProperties.getOps().get(0))
                                .getUsernameClaim()).getName(),
                        authenticatedPrincipal.getAttributes(),
                        (Collection<GrantedAuthority>) authenticatedPrincipal.getAuthorities()),
                    new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        introspectedToken,
                        Instant.ofEpochSecond(((Integer) authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT)).longValue()),
                        Instant.ofEpochSecond(((Integer) authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP)).longValue())),
                    authoritiesConverter.convert(authenticatedPrincipal.getAttributes())));
    }

    /**
     * FIXME: use only the new CORS properties at next major release
     */
    @Conditional(DefaultCorsWebFilterCondition.class)
    @Bean
    CorsWebFilter corsFilter(SpringAddonsOidcProperties addonsProperties) {
        final var corsProps = new ArrayList<>(addonsProperties.getCors());
        final var deprecatedClientCorsProps = addonsProperties.getResourceserver().getCors();
        corsProps.addAll(deprecatedClientCorsProps);

        return ReactiveConfigurationSupport.getCorsFilterBean(corsProps);
    }
}
