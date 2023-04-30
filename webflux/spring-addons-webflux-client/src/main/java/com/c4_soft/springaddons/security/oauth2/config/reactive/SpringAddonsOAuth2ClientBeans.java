package com.c4_soft.springaddons.security.oauth2.config.reactive;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.session.DefaultWebSessionManager;
import org.springframework.web.server.session.InMemoryWebSessionStore;
import org.springframework.web.server.session.WebSessionManager;
import org.springframework.web.server.session.WebSessionStore;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSet2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.OAuth2AuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.CorsProperties;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * The following {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBeans} are auto-configured
 * <ul>
 * <li>springAddonsClientFilterChain: a {@link SecurityWebFilterChain}. Instantiated only if "com.c4-soft.springaddons.security.client.security-matchers"
 * property has at least one entry. If defined, it is with a high precedence, to ensure that all routes defined in this security matcher property are
 * intercepted by this filter-chain.</li>
 * <li>logoutRequestUriBuilder: builder for <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a> queries, taking
 * configuration from properties for OIDC providers which do not strictly comply with the spec: logout URI not provided by OIDC conf or non standard parameter
 * names (Auth0 and Cognito are samples of such OPs)</li>
 * <li>logoutSuccessHandler: a {@link ServerLogoutSuccessHandler}. Default instance is a {@link SpringAddonsOAuth2ServerLogoutSuccessHandler} which logs a user
 * out from the last authorization server he logged on</li>
 * <li>authoritiesConverter: an {@link OAuth2AuthoritiesConverter}. Default instance is a {@link ConfigurableClaimSet2AuthoritiesConverter} which reads
 * spring-addons {@link SpringAddonsSecurityProperties}</li>
 * <li>grantedAuthoritiesMapper: a {@link GrantedAuthoritiesMapper} using the already configured {@link OAuth2AuthoritiesConverter}</li>
 * <li>oAuth2AuthorizedClientRepository: a {@link SpringAddonsServerOAuth2AuthorizedClientRepository} (which is also a session listener) capable of handling
 * multi-tenancy and back-channel logout.</li>
 * <li>csrfCookieWebFilter: a {@link WebFilter} to set the CSRF cookie if "com.c4-soft.springaddons.security.client.csrf" is set to cookie</li>
 * <li>clientAuthorizePostProcessor: a {@link ClientAuthorizeExchangeSpecPostProcessor} post processor to fine tune access control from java configuration. It
 * applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated.</li>
 * <li>clientHttpPostProcessor: a {@link ClientHttpSecurityPostProcessor} to override anything from above auto-configuration. It is called just before the
 * security filter-chain is returned. Default is a no-op.</li>
 * <li>webSessionStore: a {@link SpringAddonsWebSessionStore} which is a proxy for {@link InMemoryWebSessionStore}, also accepting {@link WebSessionListener
 * session listeners} to register themself and be notified of sessions "create" and "remove" events</li>
 * <li>webSessionManager: a {@link WebSessionManager} relying on the above {@link SpringAddonsWebSessionStore}</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnProperty(matchIfMissing = true, prefix = "com.c4-soft.springaddons.security.client", name = "enabled")
@EnableWebFluxSecurity
@AutoConfiguration
@Import({ SpringAddonsOAuth2ClientProperties.class })
@Slf4j
public class SpringAddonsOAuth2ClientBeans {

	@ConditionalOnExpression("!(T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers:}') && T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers[0]:}'))")
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	@Bean
	SecurityWebFilterChain clientFilterChain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsOAuth2ClientProperties clientProperties,
			ServerLogoutSuccessHandler logoutSuccessHandler,
			ClientAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
			ClientHttpSecurityPostProcessor httpPostProcessor)
			throws Exception {

		final var clientRoutes = Stream.of(clientProperties.getSecurityMatchers()).map(PathPatternParserServerWebExchangeMatcher::new)
				.toArray(PathPatternParserServerWebExchangeMatcher[]::new);
		log.info("Applying client OAuth2 configuration for: {}", (Object[]) clientProperties.getSecurityMatchers());
		http.securityMatcher(new OrServerWebExchangeMatcher(clientRoutes));

		// @formatter:off
        clientProperties.getLoginPath().ifPresent(loginPath -> {
        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint(UriComponentsBuilder.fromUri(clientProperties.getClientUri()).path(loginPath).build().toString())));
        });

        http.oauth2Login(oauth2 -> {
            clientProperties.getPostLoginRedirectPath().ifPresent(postLoginRedirectPath -> {
                oauth2.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler(UriComponentsBuilder.fromUri(clientProperties.getClientUri()).path(postLoginRedirectPath).build().toString()));
            });
            clientProperties.getLoginPath().ifPresent(loginPath -> {
                oauth2.authenticationFailureHandler(new RedirectServerAuthenticationFailureHandler(UriComponentsBuilder.fromUri(clientProperties.getClientUri()).path(loginPath).build().toString()));
            });
        });

        http.logout(logout -> logout.logoutSuccessHandler(logoutSuccessHandler));

        ReactiveConfigurationSupport.configureClient(http, serverProperties, clientProperties, authorizePostProcessor, httpPostProcessor);

        return http.build();
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
    LogoutRequestUriBuilder logoutRequestUriBuilder(SpringAddonsOAuth2ClientProperties clientProps) {
        return new SpringAddonsOAuth2LogoutRequestUriBuilder(clientProps);
    }

    /**
     * Single tenant logout handler for OIDC provider complying to <a href=
     * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
     * Logout</a> (or approximately complying to it like Auth0 or Cognito)
     *
     * @param logoutRequestUriBuilder      delegate doing the smart job
     * @param clientRegistrationRepository
     * @return {@link SpringAddonsOAuth2ServerLogoutSuccessHandler}
     */
    @ConditionalOnMissingBean
    @Bean
    ServerLogoutSuccessHandler logoutSuccessHandler(LogoutRequestUriBuilder logoutUriBuilder,
            ReactiveClientRegistrationRepository clientRegistrationRepo) {
        return new SpringAddonsOAuth2ServerLogoutSuccessHandler(logoutUriBuilder, clientRegistrationRepo);
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
     * @param corsProperties the properties to pick CORS configuration from
     * @return a CORS configuration built from properties
     */
    CorsConfigurationSource corsConfig(CorsProperties[] corsProperties) {
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
     *
     * @param clientRegistrationRepository the OIDC providers configuration
     * @return {@link SpringAddonsServerOAuth2AuthorizedClientRepository}, an
     *         authorized
     *         client repository supporting multi-tenancy and exposing the required
     *         API for back-channel logout
     */
    @ConditionalOnMissingBean
    @Bean
    ServerOAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            SpringAddonsWebSessionStore webSessionStore) {
        return new SpringAddonsServerOAuth2AuthorizedClientRepository(clientRegistrationRepository, webSessionStore);
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
    ClientAuthorizeExchangeSpecPostProcessor clientAuthorizePostProcessor() {
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
    ClientHttpSecurityPostProcessor clientHttpPostProcessor() {
        return serverHttpSecurity -> serverHttpSecurity;
    }

    /**
     * https://docs.spring.io/spring-security/reference/5.8/migration/reactive.html#_i_am_using_angularjs_or_another_javascript_framework
     */
    @Conditional(CookieCsrf.class)
    @ConditionalOnMissingBean(name = "csrfCookieWebFilter")
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

    @ConditionalOnMissingBean
    @Bean
    WebSessionManager webSessionManager(WebSessionStore webSessionStore) {
        DefaultWebSessionManager webSessionManager = new DefaultWebSessionManager();
        webSessionManager.setSessionStore(webSessionStore);
        return webSessionManager;
    }

    @ConditionalOnMissingBean
    @Bean
    SpringAddonsWebSessionStore webSessionStore(ServerProperties serverProperties) {
        return new SpringAddonsWebSessionStore(serverProperties.getReactive().getSession().getTimeout());
    }

    public static interface WebSessionListener {
        default void sessionCreated(WebSession session) {
        }

        default void sessionRemoved(String sessionId) {
        }
    }

    /**
     * A {@link WebSessionStore} using {@link InMemoryWebSessionStore} as delegate
     * and notifying registered {@link WebSessionListener session listeners} with
     * sessions "create" and "remove" events.
     *
     * @author Jerome Wacongne ch4mp&#64;c4-soft.com
     *
     */
    public static class SpringAddonsWebSessionStore implements WebSessionStore {
        private final InMemoryWebSessionStore delegate = new InMemoryWebSessionStore();
        private final ConcurrentLinkedQueue<WebSessionListener> webSessionListeners = new ConcurrentLinkedQueue<WebSessionListener>();

        private final Duration timeout;

        public SpringAddonsWebSessionStore(Duration timeout) {
            this.timeout = timeout;
        }

        public void addWebSessionListener(WebSessionListener listener) {
            webSessionListeners.add(listener);
        }

        @Override
        public Mono<WebSession> createWebSession() {
            return delegate.createWebSession().doOnSuccess(this::setMaxIdleTime)
                    .doOnSuccess(session -> webSessionListeners.forEach(l -> l.sessionCreated(session)));
        }

        @Override
        public Mono<WebSession> retrieveSession(String sessionId) {
            return delegate.retrieveSession(sessionId);
        }

        @Override
        public Mono<Void> removeSession(String sessionId) {
            webSessionListeners.forEach(l -> l.sessionRemoved(sessionId));
            return delegate.removeSession(sessionId);
        }

        @Override
        public Mono<WebSession> updateLastAccessTime(WebSession webSession) {
            return delegate.updateLastAccessTime(webSession);
        }

        private void setMaxIdleTime(WebSession session) {
            session.setMaxIdleTime(this.timeout);
        }
    }
}