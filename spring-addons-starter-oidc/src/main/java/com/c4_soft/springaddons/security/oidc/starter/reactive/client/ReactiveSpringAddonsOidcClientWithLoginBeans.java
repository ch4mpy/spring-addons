package com.c4_soft.springaddons.security.oidc.starter.reactive.client;

import java.util.Optional;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.WebFilter;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.CookieCsrfCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationSuccessHandlerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsClientWithLoginCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsNotServlet;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveConfigurationSupport;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveSpringAddonsOidcBeans;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * The following {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBeans} are auto-configured
 * <ul>
 * <li>springAddonsClientFilterChain: a {@link SecurityWebFilterChain}. Instantiated only if
 * "com.c4-soft.springaddons.oidc.client.security-matchers" property has at least one entry. If defined, it is with a high precedence, to
 * ensure that all routes defined in this security matcher property are intercepted by this filter-chain.</li>
 * <li>logoutRequestUriBuilder: builder for <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a>
 * queries, taking configuration from properties for OIDC providers which do not strictly comply with the spec: logout URI not provided by
 * OIDC conf or non standard parameter names (Auth0 and Cognito are samples of such OPs)</li>
 * <li>logoutSuccessHandler: a {@link ServerLogoutSuccessHandler}. Default instance is a {@link SpringAddonsServerLogoutSuccessHandler}
 * which logs a user out from the last authorization server he logged on</li>
 * <li>authoritiesConverter: an {@link ClaimSetAuthoritiesConverter}. Default instance is a {@link ConfigurableClaimSetAuthoritiesConverter}
 * which reads spring-addons {@link SpringAddonsOidcProperties}</li>
 * <li>csrfCookieWebFilter: a {@link WebFilter} to set the CSRF cookie if "com.c4-soft.springaddons.oidc.client.csrf" is set to cookie</li>
 * <li>clientAuthorizePostProcessor: a {@link ClientAuthorizeExchangeSpecPostProcessor} post processor to fine tune access control from java
 * configuration. It applies to all routes not listed in "permit-all" property configuration. Default requires users to be
 * authenticated.</li>
 * <li>clientHttpPostProcessor: a {@link ClientHttpSecurityPostProcessor} to override anything from above auto-configuration. It is called
 * just before the security filter-chain is returned. Default is a no-op.</li>
 * <li>authorizationRequestResolver: a {@link ServerOAuth2AuthorizationRequestResolver} to add custom parameters (from application
 * properties) to authorization code request</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@Conditional({ IsClientWithLoginCondition.class, IsNotServlet.class })
@EnableWebFluxSecurity
@AutoConfiguration
@ImportAutoConfiguration(ReactiveSpringAddonsOidcBeans.class)
@Slf4j
public class ReactiveSpringAddonsOidcClientWithLoginBeans {

	/**
	 * <p>
	 * Instantiated only if "com.c4-soft.springaddons.oidc.client.security-matchers" property has at least one entry. If defined, it is with
	 * higher precedence than resource server one.
	 * </p>
	 * It defines:
	 * <ul>
	 * <li>If the path to login page was provided in conf, a &#64;Controller must be provided to handle it. Otherwise Spring Boot default
	 * generated one is used</li>
	 * <li>logout (using {@link SpringAddonsServerLogoutSuccessHandler} by default)</li>
	 * <li>forces SSL usage if it is enabled</li> properties</li>
	 * <li>CSRF protection as defined in spring-addons <b>client</b> properties (enabled by default in this filter-chain).</li>
	 * <li>allow access to unauthorized requests to path matchers listed in spring-security <b>client</b> "permit-all" property</li>
	 * <li>as usual, apply {@link ClientAuthorizeExchangeSpecPostProcessor} for access control configuration from Java conf and
	 * {@link ClientHttpSecurityPostProcessor} to override anything from the auto-configuration listed above</li>
	 * </ul>
	 *
	 * @param  http                                 the security filter-chain builder to configure
	 * @param  serverProperties                     Spring Boot standard server properties
	 * @param  authorizationRequestResolver         the authorization request resolver to use. By default
	 *                                              {@link ServerOAuth2AuthorizationRequestResolver} (adds authorization request parameters
	 *                                              defined in properties and builds absolutes callback URI). By default, a
	 *                                              {@link SpringAddonsServerOAuth2AuthorizationRequestResolver} is used
	 * @param  preAuthorizationCodeRedirectStrategy the redirection strategy to use for authorization-code request
	 * @param  authenticationSuccessHandler         the authentication success handler to use. By default, a
	 *                                              {@link SpringAddonsOauth2ServerAuthenticationSuccessHandler} is used.
	 * @param  authenticationFailureHandler         the authentication failure handler to use. By default, a
	 *                                              {@link SpringAddonsOauth2ServerAuthenticationFailureHandler} is used.
	 * @param  logoutSuccessHandler                 Defaulted to {@link SpringAddonsServerLogoutSuccessHandler} which can handle "almost" RP
	 *                                              Initiated Logout conformant OPs (like Auth0 and Cognito)
	 * @param  addonsProperties                     {@link SpringAddonsOAuth2ClientProperties spring-addons client properties}
	 * @param  authorizePostProcessor               post process authorization after "permit-all" configuration was applied (default is
	 *                                              "isAuthenticated()" to everything that was not matched)
	 * @param  httpPostProcessor                    post process the "http" builder just before it is returned (enables to override anything
	 *                                              from the auto-configuration) spring-addons client properties}
	 * @param  oidcLogoutCustomizer                 a configurer for Spring Security Back-Channel Logout implementation
	 * @return                                      a security filter-chain scoped to specified security-matchers and adapted to OAuth2 clients
	 * @throws Exception                            in case of miss-configuration
	 */
	@Order(Ordered.LOWEST_PRECEDENCE - 1)
	@Bean
	SecurityWebFilterChain clientFilterChain(
			ServerHttpSecurity http,
			ServerProperties serverProperties,
			SpringAddonsOidcProperties addonsProperties,
			ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
			PreAuthorizationCodeServerRedirectStrategy preAuthorizationCodeRedirectStrategy,
			Optional<ServerAuthenticationSuccessHandler> authenticationSuccessHandler,
			Optional<ServerAuthenticationFailureHandler> authenticationFailureHandler,
			ServerLogoutSuccessHandler logoutSuccessHandler,
			ClientAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
			ClientHttpSecurityPostProcessor httpPostProcessor,
			Optional<ServerLogoutHandler> logoutHandler,
			Customizer<ServerHttpSecurity.OidcLogoutSpec> oidcLogoutCustomizer)
			throws Exception {

		final var clientRoutes = addonsProperties.getClient().getSecurityMatchers().stream().map(PathPatternParserServerWebExchangeMatcher::new)
				.map(ServerWebExchangeMatcher.class::cast).toList();
		log.info("Applying client OAuth2 configuration for: {}", addonsProperties.getClient().getSecurityMatchers());
		http.securityMatcher(new OrServerWebExchangeMatcher(clientRoutes));

		// @formatter:off
        addonsProperties.getClient().getLoginPath().ifPresent(loginPath -> {
        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint(UriComponentsBuilder.fromUri(addonsProperties.getClient().getClientUri()).path(loginPath).build().toString())));
        });

        http.oauth2Login(oauth2 -> {
        	oauth2.authorizationRequestResolver(authorizationRequestResolver);
            oauth2.authorizationRedirectStrategy(preAuthorizationCodeRedirectStrategy);
            authenticationSuccessHandler.ifPresent(oauth2::authenticationSuccessHandler);
            authenticationFailureHandler.ifPresent(oauth2::authenticationFailureHandler);
        });

        http.logout((logout) -> {
        	logoutHandler.ifPresent(logout::logoutHandler);
        	logout.logoutSuccessHandler(logoutSuccessHandler);
        });

        if(addonsProperties.getClient().getBackChannelLogout().isEnabled()) {
        	http.oidcLogout((logout) -> {
				logout.backChannel(Customizer.withDefaults());
			});
        }

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
            ReactiveClientRegistrationRepository clientRegistrationRepo, SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsServerLogoutSuccessHandler(logoutUriBuilder, clientRegistrationRepo, addonsProperties);
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
            exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty()).subscribe();
            return chain.filter(exchange);
        };
    }

    @ConditionalOnMissingBean
    @Bean
    ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository, SpringAddonsOidcProperties addonsProperties) {
    	return new SpringAddonsServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository, addonsProperties.getClient());
    }

    @ConditionalOnMissingBean
    @Bean
    PreAuthorizationCodeServerRedirectStrategy preAuthorizationCodeRedirectStrategy(SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsPreAuthorizationCodeServerRedirectStrategy(
            addonsProperties.getClient().getOauth2Redirections().getPreAuthorizationCode());
    }

    @Conditional(DefaultAuthenticationSuccessHandlerCondition.class)
    @Bean
    ServerAuthenticationSuccessHandler authenticationSuccessHandler(SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsOauth2ServerAuthenticationSuccessHandler(addonsProperties);
    }

    @Conditional(DefaultAuthenticationSuccessHandlerCondition.class)
    @Bean
    ServerAuthenticationFailureHandler authenticationFailureHandler(SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsOauth2ServerAuthenticationFailureHandler(addonsProperties);
    }

    public static interface PreAuthorizationCodeServerRedirectStrategy extends ServerRedirectStrategy {}

    public static class SpringAddonsPreAuthorizationCodeServerRedirectStrategy extends SpringAddonsOauth2ServerRedirectStrategy implements PreAuthorizationCodeServerRedirectStrategy {
        public SpringAddonsPreAuthorizationCodeServerRedirectStrategy(HttpStatus defaultStatus) {
            super(defaultStatus);
        }

    }

    @ConditionalOnMissingBean
    @Bean
    Customizer<ServerHttpSecurity.OidcLogoutSpec> oidcLogoutSpec() {
        return Customizer.withDefaults();
    }
}