package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.time.Duration;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.session.DefaultWebSessionManager;
import org.springframework.web.server.session.InMemoryWebSessionStore;
import org.springframework.web.server.session.WebSessionManager;
import org.springframework.web.server.session.WebSessionStore;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.CookieCsrfCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsNotServlet;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcClientCondition;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveConfigurationSupport;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveSpringAddonsOidcBeans;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * The following {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBeans} are auto-configured
 * <ul>
 * <li>springAddonsClientFilterChain: a {@link SecurityWebFilterChain}. Instantiated only if "com.c4-soft.springaddons.oidc.client.security-matchers" property
 * has at least one entry. If defined, it is with a high precedence, to ensure that all routes defined in this security matcher property are intercepted by this
 * filter-chain.</li>
 * <li>logoutRequestUriBuilder: builder for <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a> queries, taking
 * configuration from properties for OIDC providers which do not strictly comply with the spec: logout URI not provided by OIDC conf or non standard parameter
 * names (Auth0 and Cognito are samples of such OPs)</li>
 * <li>logoutSuccessHandler: a {@link ServerLogoutSuccessHandler}. Default instance is a {@link SpringAddonsServerLogoutSuccessHandler} which logs a user out
 * from the last authorization server he logged on</li>
 * <li>authoritiesConverter: an {@link ClaimSetAuthoritiesConverter}. Default instance is a {@link ConfigurableClaimSetAuthoritiesConverter} which reads
 * spring-addons {@link SpringAddonsOidcProperties}</li>
 * <li>oAuth2AuthorizedClientRepository: a {@link SpringAddonsServerOAuth2AuthorizedClientRepository} (which is also a session listener) capable of handling
 * multi-tenancy and back-channel logout.</li>
 * <li>csrfCookieWebFilter: a {@link WebFilter} to set the CSRF cookie if "com.c4-soft.springaddons.oidc.client.csrf" is set to cookie</li>
 * <li>clientAuthorizePostProcessor: a {@link ClientAuthorizeExchangeSpecPostProcessor} post processor to fine tune access control from java configuration. It
 * applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated.</li>
 * <li>clientHttpPostProcessor: a {@link ClientHttpSecurityPostProcessor} to override anything from above auto-configuration. It is called just before the
 * security filter-chain is returned. Default is a no-op.</li>
 * <li>webSessionStore: a {@link SpringAddonsWebSessionStore} which is a proxy for {@link InMemoryWebSessionStore}, also accepting {@link WebSessionListener
 * session listeners} to register themself and be notified of sessions "create" and "remove" events</li>
 * <li>webSessionManager: a {@link WebSessionManager} relying on the above {@link SpringAddonsWebSessionStore}</li>
 * <li>authorizationRequestResolver: a {@link ServerOAuth2AuthorizationRequestResolver} to add custom parameters (from application properties) to authorization
 * code request</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Conditional({ IsOidcClientCondition.class, IsNotServlet.class })
@EnableWebFluxSecurity
@AutoConfiguration
@ImportAutoConfiguration(ReactiveSpringAddonsOidcBeans.class)
@Slf4j
public class ReactiveSpringAddonsOidcClientBeans {

	/**
	 * <p>
	 * Instantiated only if "com.c4-soft.springaddons.oidc.client.security-matchers" property has at least one entry. If defined, it is with higher precedence
	 * than resource server one.
	 * </p>
	 * It defines:
	 * <ul>
	 * <li>If the path to login page was provided in conf, a &#64;Controller must be provided to handle it. Otherwise Spring Boot default generated one is
	 * used</li>
	 * <li>logout (using {@link SpringAddonsServerLogoutSuccessHandler} by default)</li>
	 * <li>forces SSL usage if it is enabled</li> properties</li>
	 * <li>CSRF protection as defined in spring-addons <b>client</b> properties (enabled by default in this filter-chain).</li>
	 * <li>allow access to unauthorized requests to path matchers listed in spring-security <b>client</b> "permit-all" property</li>
	 * <li>as usual, apply {@link ClientAuthorizeExchangeSpecPostProcessor} for access control configuration from Java conf and
	 * {@link ClientHttpSecurityPostProcessor} to override anything from the auto-configuration listed above</li>
	 * </ul>
	 *
	 * @param  http                         the security filter-chain builder to configure
	 * @param  serverProperties             Spring Boot standard server properties
	 * @param  authorizationRequestResolver the authorization request resolver to use. By default {@link ServerOAuth2AuthorizationRequestResolver} (adds
	 *                                      authorization request parameters defined in properties and builds absolutes callback URI)
	 * @param  logoutSuccessHandler         Defaulted to {@link SpringAddonsServerLogoutSuccessHandler} which can handle "almost" RP Initiated Logout conformant
	 *                                      OPs (like Auth0 and Cognito)
	 * @param  addonsProperties             {@link SpringAddonsOAuth2ClientProperties spring-addons client properties}
	 * @param  authorizePostProcessor       post process authorization after "permit-all" configuration was applied (default is "isAuthenticated()" to
	 *                                      everything that was not matched)
	 * @param  httpPostProcessor            post process the "http" builder just before it is returned (enables to override anything from the
	 *                                      auto-configuration) spring-addons client properties}
	 * @return                              a security filter-chain scoped to specified security-matchers and adapted to OAuth2 clients
	 * @throws Exception                    in case of miss-configuration
	 */
	@Order(Ordered.LOWEST_PRECEDENCE - 1)
	@Bean
	SecurityWebFilterChain clientFilterChain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsOidcProperties addonsProperties,
			ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
			ServerLogoutSuccessHandler logoutSuccessHandler,
			ClientAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
			ClientHttpSecurityPostProcessor httpPostProcessor)
			throws Exception {

		final var clientRoutes = Stream.of(addonsProperties.getClient().getSecurityMatchers()).map(PathPatternParserServerWebExchangeMatcher::new)
				.toArray(PathPatternParserServerWebExchangeMatcher[]::new);
		log.info("Applying client OAuth2 configuration for: {}", (Object[]) addonsProperties.getClient().getSecurityMatchers());
		http.securityMatcher(new OrServerWebExchangeMatcher(clientRoutes));

		// @formatter:off
        addonsProperties.getClient().getLoginPath().ifPresent(loginPath -> {
        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint(UriComponentsBuilder.fromUri(addonsProperties.getClient().getClientUri()).path(loginPath).build().toString())));
        });

        http.oauth2Login(oauth2 -> {
        	oauth2.authorizationRequestResolver(authorizationRequestResolver);
            addonsProperties.getClient().getPostLoginRedirectPath().ifPresent(postLoginRedirectPath -> {
                oauth2.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler(UriComponentsBuilder.fromUri(addonsProperties.getClient().getClientUri()).path(postLoginRedirectPath).build().toString()));
            });
            addonsProperties.getClient().getLoginPath().ifPresent(loginPath -> {
                oauth2.authenticationFailureHandler(new RedirectServerAuthenticationFailureHandler(UriComponentsBuilder.fromUri(addonsProperties.getClient().getClientUri()).path(loginPath).build().toString()));
            });
        });

        http.logout(logout -> logout.logoutSuccessHandler(logoutSuccessHandler));

        ReactiveConfigurationSupport.configureClient(http, serverProperties, addonsProperties.getClient(), authorizePostProcessor, httpPostProcessor);

        return http.build();
    }

    /**
     * Build logout request for <a href=
     * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
     * Logout</a>. It works with most OIDC provider: those complying with the spec
     * (Keycloak for instance), off course, but also those which are close enough to
     * it (Auth0, Cognito, ...)
     *
     * @param addonsProperties {@link SpringAddonsOAuth2ClientProperties} to pick logout
     *                    configuration for divergence to the standard (logout URI
     *                    not provided in .well-known/openid-configuration and
     *                    non-conform parameter names)
     * @return {@link SpringAddonsOAuth2LogoutRequestUriBuilder]
     */
    @ConditionalOnMissingBean
    @Bean
    LogoutRequestUriBuilder logoutRequestUriBuilder(SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsOAuth2LogoutRequestUriBuilder(addonsProperties.getClient());
    }

    /**
     * Single tenant logout handler for OIDC provider complying to <a href=
     * "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
     * Logout</a> (or approximately complying to it like Auth0 or Cognito)
     *
     * @param logoutRequestUriBuilder      delegate doing the smart job
     * @param clientRegistrationRepository
     * @return {@link SpringAddonsServerLogoutSuccessHandler}
     */
    @ConditionalOnMissingBean
    @Bean
    ServerLogoutSuccessHandler logoutSuccessHandler(LogoutRequestUriBuilder logoutUriBuilder,
            ReactiveClientRegistrationRepository clientRegistrationRepo) {
        return new SpringAddonsServerLogoutSuccessHandler(logoutUriBuilder, clientRegistrationRepo);
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
    @Conditional(CookieCsrfCondition.class)
    @ConditionalOnMissingBean(name = "csrfCookieWebFilter")
    @Bean
    WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> csrfToken = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
            return csrfToken.doOnSuccess(token -> {
            }).then(chain.filter(exchange));
        };
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

    @ConditionalOnMissingBean
    @Bean
    ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(InMemoryReactiveClientRegistrationRepository clientRegistrationRepository, SpringAddonsOidcProperties addonsProperties) {
    	return new SpringAddonsServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository, addonsProperties.getClient());
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