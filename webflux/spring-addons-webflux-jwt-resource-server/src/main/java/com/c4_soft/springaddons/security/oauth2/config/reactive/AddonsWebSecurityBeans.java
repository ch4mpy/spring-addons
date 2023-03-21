package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

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
 * <li><b>SecurityWebFilterChain</b>: applies CORS, CSRF, anonymous,
 * sessionCreationPolicy, SSL redirect and 401 instead of redirect to
 * login properties as defined in {@link SpringAddonsSecurityProperties}</li>
 * <li><b>AuthorizeExchangeSpecPostProcessor</b>. Override if you need fined
 * grained HTTP security (more than authenticated() to all routes
 * but the ones defined as permitAll() in
 * {@link SpringAddonsSecurityProperties}</li>
 * <li><b>Jwt2AuthoritiesConverter</b>: responsible for converting the JWT into
 * Collection&lt;? extends GrantedAuthority&gt;</li>
 * <li><b>ReactiveJwt2OpenidClaimSetConverter&lt;T extends Map&lt;String,
 * Object&gt; &amp; Serializable&gt;</b>: responsible for converting
 * the JWT into a claim-set of your choice (OpenID or not)</li>
 * <li><b>ReactiveJwt2AuthenticationConverter&lt;OAuthentication&lt;T extends
 * OpenidClaimSet&gt;&gt;</b>: responsible for converting the JWT
 * into an Authentication (uses both beans above)</li>
 * <li><b>ReactiveAuthenticationManagerResolver</b>: required to be able to
 * define more than one token issuer until
 * https://github.com/spring-projects/spring-boot/issues/30108 is solved</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@EnableWebFluxSecurity
@AutoConfiguration
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
     * @param accessDeniedHandler           handler for unauthorized requests
     *                                      (missing or invalid access-token)
     * @return A default {@link SecurityWebFilterChain} for reactive
     *         resource-servers with JWT decoder(matches all unmatched routes with
     *         lowest precedence)
     */
    @Order(Ordered.LOWEST_PRECEDENCE)
    @Bean
    SecurityWebFilterChain springAddonsResourceServerSecurityFilterChain(
            ServerHttpSecurity http,
            ServerProperties serverProperties,
            SpringAddonsSecurityProperties addonsProperties,
            AuthorizeExchangeSpecPostProcessor authorizePostProcessor,
            ServerHttpSecurityPostProcessor httpPostProcessor,
            ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver,
            ServerAccessDeniedHandler accessDeniedHandler,
            CorsConfigurationSource corsConfigurationSource) {

        http.oauth2ResourceServer().authenticationManagerResolver(authenticationManagerResolver);

        if (addonsProperties.getPermitAll().length > 0) {
            http.anonymous();
        }

        if (addonsProperties.getCors().length > 0) {
            http.cors().configurationSource(corsConfigurationSource);
        } else {
            http.cors().disable();
        }

        var delegate = new XorServerCsrfTokenRequestAttributeHandler();
        switch (addonsProperties.getCsrf()) {
            case DISABLE:
                http.csrf().disable();
                break;
            case DEFAULT:
                if (addonsProperties.isStatlessSessions()) {
                    http.csrf().disable();
                } else {
                    http.csrf();
                }
                break;
            case SESSION:
                http.csrf();
                break;
            case COOKIE_HTTP_ONLY:
                // https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework
                http.csrf(csrf -> csrf.csrfTokenRepository(new CookieServerCsrfTokenRepository())
                        .csrfTokenRequestHandler(delegate::handle));
                break;
            case COOKIE_ACCESSIBLE_FROM_JS:
                // https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework
                http.csrf(csrf -> csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(delegate::handle));
                break;
        }

        if (addonsProperties.isStatlessSessions()) {
            http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
        }

        http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);

        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.redirectToHttps();
        }

        authorizePostProcessor
                .authorizeHttpRequests(addonsProperties.getPermitAll().length == 0 ? http.authorizeExchange()
                        : http.authorizeExchange().pathMatchers(addonsProperties.getPermitAll()).permitAll());

        return httpPostProcessor.process(http).build();
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
    AuthorizeExchangeSpecPostProcessor authorizePostProcessor() {
        return (ServerHttpSecurity.AuthorizeExchangeSpec spec) -> spec.anyExchange().authenticated();
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
    ServerHttpSecurityPostProcessor httpPostProcessor() {
        return serverHttpSecurity -> serverHttpSecurity;
    }

    @ConditionalOnMissingBean
    @Bean
    CorsConfigurationSource corsConfigurationSource(SpringAddonsSecurityProperties addonsProperties) {
        log.debug("Building default CorsConfigurationSource with: {}",
                Stream.of(addonsProperties.getCors()).toList());
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

    public static interface Jwt2AuthenticationConverter extends Converter<Jwt, Mono<AbstractAuthenticationToken>> {
    }

    /**
     * Converter bean from {@link Jwt} to {@link AbstractAuthenticationToken}
     *
     * @param authoritiesConverter  converts access-token claims into Spring
     *                              authorities
     * @param authenticationFactory builds an {@link Authentication} instance from
     *                              access-token string and claims
     * @return a converter from {@link Jwt} to {@link AbstractAuthenticationToken}
     */
    @ConditionalOnMissingBean
    @Bean
    Jwt2AuthenticationConverter jwtAuthenticationConverter(
            Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
            Optional<OAuth2AuthenticationFactory> authenticationFactory,
            SpringAddonsSecurityProperties addonsProperties) {
        return jwt -> authenticationFactory.map(af -> af.build(jwt.getTokenValue(), jwt.getClaims()))
                .orElse(Mono.just(new JwtAuthenticationToken(
                        jwt,
                        authoritiesConverter.convert(jwt.getClaims()),
                        jwt.getClaimAsString(
                                addonsProperties.getIssuerProperties(jwt.getIssuer()).getUsernameClaim()))));
    }

    /**
     * Provides with multi-tenancy: builds a ReactiveAuthenticationManagerResolver
     * per provided OIDC issuer URI
     *
     * @param auth2ResourceServerProperties "spring.security.oauth2.resourceserver"
     *                                      configuration properties
     * @param addonsProperties              "com.c4-soft.springaddons.security"
     *                                      configuration properties
     * @param jwtAuthenticationConverter    converts from a {@link Jwt} to an
     *                                      {@link Authentication} implementation
     * @return Multi-tenant {@link ReactiveAuthenticationManagerResolver} (one for
     *         each configured issuer)
     */
    @ConditionalOnMissingBean
    @Bean
    ReactiveAuthenticationManagerResolver<ServerWebExchange> authenticationManagerResolver(
            OAuth2ResourceServerProperties auth2ResourceServerProperties,
            SpringAddonsSecurityProperties addonsProperties,
            Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter) {
        final var jwtProps = Optional.ofNullable(auth2ResourceServerProperties)
                .map(OAuth2ResourceServerProperties::getJwt);
        // @formatter:off
		Optional.ofNullable(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getIssuerUri)).orElse(jwtProps.map(OAuth2ResourceServerProperties.Jwt::getJwkSetUri))
		    .filter(StringUtils::hasLength)
		    .ifPresent(jwtConf -> {
				log.warn("spring.security.oauth2.resourceserver configuration will be ignored in favor of com.c4-soft.springaddons.security");
			});
		// @formatter:on

        final Map<String, Mono<ReactiveAuthenticationManager>> jwtManagers = Stream.of(addonsProperties.getIssuers())
                .collect(Collectors.toMap(issuer -> issuer.getLocation().toString(), issuer -> {
                    ReactiveJwtDecoder decoder = issuer.getJwkSetUri() != null
                            && StringUtils.hasLength(issuer.getJwkSetUri().toString())
                                    ? NimbusReactiveJwtDecoder.withJwkSetUri(issuer.getJwkSetUri().toString()).build()
                                    : ReactiveJwtDecoders.fromIssuerLocation(issuer.getLocation().toString());
                    var provider = new JwtReactiveAuthenticationManager(decoder);
                    provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
                    return Mono.just(provider);
                }));

        log.debug(
                "Building default JwtIssuerReactiveAuthenticationManagerResolver with: {} {}",
                auth2ResourceServerProperties.getJwt(),
                Stream.of(addonsProperties.getIssuers()).toList());
        return new JwtIssuerReactiveAuthenticationManagerResolver(
                issuerLocation -> jwtManagers.getOrDefault(issuerLocation, Mono.empty()));
    }

    /**
     * Bean to switch from default behavior of redirecting unauthorized
     * users to login (302) to returning 401 (unauthorized)
     *
     * @return a bean to switch from default behavior of redirecting unauthorized
     *         users to login (302) to returning 401 (unauthorized)
     */
    @ConditionalOnMissingBean
    @Bean
    ServerAccessDeniedHandler serverAccessDeniedHandler() {
        log.debug("Building default ServerAccessDeniedHandler");
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

    /**
     * https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework
     */
    @Conditional(CookieCsrf.class)
    @Bean
    WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
            return csrfToken.doOnSuccess(token -> {
            }).then(chain.filter(exchange));
        };
    }

    static class CookieCsrf extends AnyNestedCondition {

        public CookieCsrf() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @ConditionalOnProperty(name = "com.c4-soft.springaddons.security.client.csrf", havingValue = "cookie-accessible-from-js")
        static class Value1Condition {

        }

        @ConditionalOnProperty(name = "com.c4-soft.springaddons.security.client.csrf", havingValue = "cookie-http-only")
        static class Value2Condition {

        }

    }
}