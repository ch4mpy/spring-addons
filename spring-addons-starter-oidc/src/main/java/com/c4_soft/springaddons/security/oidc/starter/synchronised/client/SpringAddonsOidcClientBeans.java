package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.util.Optional;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationFailureHandlerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationSuccessHandlerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcClientCondition;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.ServletConfigurationSupport;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.SpringAddonsOidcBeans;

import lombok.extern.slf4j.Slf4j;

/**
 * The following {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBeans} are auto-configured
 * <ul>
 * <li>springAddonsClientFilterChain: a {@link SecurityFilterChain}. Instantiated only if "com.c4-soft.springaddons.oidc.client.security-matchers" property has
 * at least one entry. If defined, it is with highest precedence, to ensure that all routes defined in this security matcher property are intercepted by this
 * filter-chain.</li>
 * <li>oAuth2AuthorizationRequestResolver: a {@link OAuth2AuthorizationRequestResolver}. Default instance is a
 * {@link SpringAddonsOAuth2AuthorizationRequestResolver} which sets the client hostname in the redirect URI with
 * {@link SpringAddonsOidcClientProperties#clientUri SpringAddonsOidcClientProperties#client-uri}</li>
 * <li>logoutRequestUriBuilder: builder for <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a> queries, taking
 * configuration from properties for OIDC providers which do not strictly comply with the spec: logout URI not provided by OIDC conf or non standard parameter
 * names (Auth0 and Cognito are samples of such OPs)</li>
 * <li>logoutSuccessHandler: a {@link LogoutSuccessHandler}. Default instance is a {@link SpringAddonsLogoutSuccessHandler} which logs a user out from the last
 * authorization server he logged on.</li>
 * <li>authoritiesConverter: an {@link ClaimSetAuthoritiesConverter}. Default instance is a {@link ConfigurableClaimSetAuthoritiesConverter} which reads
 * spring-addons {@link SpringAddonsOidcProperties}</li>
 * <li>clientAuthorizePostProcessor: a {@link ClientExpressionInterceptUrlRegistryPostProcessor} post processor to fine tune access control from java
 * configuration. It applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated.</li>
 * <li>clientHttpPostProcessor: a {@link ClientHttpSecurityPostProcessor} to override anything from above auto-configuration. It is called just before the
 * security filter-chain is returned. Default is a no-op.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnWebApplication(type = Type.SERVLET)
@Conditional(IsOidcClientCondition.class)
@EnableWebSecurity
@AutoConfiguration
@ImportAutoConfiguration(SpringAddonsOidcBeans.class)
@Slf4j
public class SpringAddonsOidcClientBeans {

    /**
     * <p>
     * Instantiated only if "com.c4-soft.springaddons.oidc.client.security-matchers" property has at least one entry. If defined, it is with higher precedence
     * than resource server one.
     * </p>
     * It defines:
     * <ul>
     * <li>If the path to login page was provided in conf, a &#64;Controller must be provided to handle it. Otherwise Spring Boot default generated one is used
     * (be aware that it does not work when bound to 80 or 8080 with SSL enabled, so, in that case, use another port or define a login path and a controller to
     * handle it)</li>
     * <li>logout (using {@link SpringAddonsLogoutSuccessHandler} by default)</li>
     * <li>forces SSL usage if it is enabled</li> properties</li>
     * <li>CSRF protection as defined in spring-addons <b>client</b> properties (enabled by default in this filter-chain).</li>
     * <li>allow access to unauthorized requests to path matchers listed in spring-security <b>client</b> "permit-all" property</li>
     * <li>as usual, apply {@link ClientExpressionInterceptUrlRegistryPostProcessor} for access control configuration from Java conf and
     * {@link ClientHttpSecurityPostProcessor} to override anything from the auto-configuration listed above</li>
     * </ul>
     *
     * @param http the security filter-chain builder to configure
     * @param serverProperties Spring Boot standard server properties
     * @param authorizationRequestResolver the authorization request resolver to use. By default {@link SpringAddonsOAuth2AuthorizationRequestResolver} (adds
     *            authorization request parameters defined in properties and builds absolutes callback URI)
     * @param preAuthorizationCodeRedirectStrategy the redirection strategy to use for authorization-code request
     * @param authenticationSuccessHandler the authentication success handler to use. Default is a {@link SpringAddonsOauth2AuthenticationSuccessHandler}
     * @param authenticationFailureHandler the authentication failure handler to use. Default is a {@link SpringAddonsOauth2AuthenticationFailureHandler}
     * @param logoutSuccessHandler Defaulted to {@link SpringAddonsLogoutSuccessHandler} which can handle "almost" RP Initiated Logout conformant OPs (like
     *            Auth0 and Cognito). Default is a {@link SpringAddonsLogoutSuccessHandler}
     * @param addonsProperties {@link SpringAddonsOAuth2ClientProperties spring-addons client properties}
     * @param authorizePostProcessor post process authorization after "permit-all" configuration was applied (default is "isAuthenticated()" to everything that
     *            was not matched)
     * @param httpPostProcessor post process the "http" builder just before it is returned (enables to override anything from the auto-configuration)
     *            spring-addons client properties}
     * @return a security filter-chain scoped to specified security-matchers and adapted to OAuth2 clients
     * @throws Exception in case of miss-configuration
     */
    @Order(Ordered.LOWEST_PRECEDENCE - 1)
    @Bean
    SecurityFilterChain springAddonsClientFilterChain(
            HttpSecurity http,
            ServerProperties serverProperties,
            PreAuthorizationCodeRedirectStrategy preAuthorizationCodeRedirectStrategy,
            OAuth2AuthorizationRequestResolver authorizationRequestResolver,
            Optional<AuthenticationSuccessHandler> authenticationSuccessHandler,
            Optional<AuthenticationFailureHandler> authenticationFailureHandler,
            LogoutSuccessHandler logoutSuccessHandler,
            SpringAddonsOidcProperties addonsProperties,
            ClientExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
            ClientHttpSecurityPostProcessor httpPostProcessor)
            throws Exception {
        // @formatter:off
        log.info("Applying client OAuth2 configuration for: {}", (Object[]) addonsProperties.getClient().getSecurityMatchers());
        http.securityMatcher(addonsProperties.getClient().getSecurityMatchers());

        http.oauth2Login(login -> {
        	login.authorizationEndpoint(authorizationEndpoint -> {
        		authorizationEndpoint.authorizationRedirectStrategy(preAuthorizationCodeRedirectStrategy);
        		authorizationEndpoint.authorizationRequestResolver(authorizationRequestResolver);
        	});
            addonsProperties.getClient().getLoginPath().ifPresent(login::loginPage);
            authenticationSuccessHandler.ifPresent(login::successHandler);
            authenticationFailureHandler.ifPresent(login::failureHandler);
        });

        http.logout(logout -> {
            logout.logoutSuccessHandler(logoutSuccessHandler);
        });
        // @formatter:on

        ServletConfigurationSupport.configureClient(http, serverProperties, addonsProperties.getClient(), authorizePostProcessor, httpPostProcessor);

        return http.build();
    }

    /**
     * Use a {@link SpringAddonsOAuth2AuthorizationRequestResolver} which:
     * <ul>
     * <li>takes hostname and port from configuration properties (and works even if SSL is enabled on port 8080)</li>
     * <li>spport defining additionl authorization request parameters from properties</li>
     * </ul>
     *
     * @param clientRegistrationRepository
     * @param addonsProperties
     * @return {@link SpringAddonsOAuth2AuthorizationRequestResolver}
     */
    @ConditionalOnMissingBean
    @Bean
    OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository,
            SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsOAuth2AuthorizationRequestResolver(clientRegistrationRepository, addonsProperties.getClient());
    }

    /**
     * Build logout request for <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a>. It works with most OIDC
     * provider: those complying with the spec (Keycloak for instance), off course, but also those which are close enough to it (Auth0, Cognito, ...)
     *
     * @param addonsProperties {@link SpringAddonsOAuth2ClientProperties} to pick logout configuration for divergence to the standard (logout URI not provided
     *            in .well-known/openid-configuration and non-conform parameter names)
     * @return {@link SpringAddonsOAuth2LogoutRequestUriBuilder]
     */
    @ConditionalOnMissingBean
    @Bean
    LogoutRequestUriBuilder logoutRequestUriBuilder(SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsOAuth2LogoutRequestUriBuilder(addonsProperties.getClient());
    }

    /**
     * Single tenant logout handler for OIDC provider complying to <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
     * Logout</a> (or approximately complying to it like Auth0 or Cognito)
     *
     * @param logoutRequestUriBuilder delegate doing the smart job
     * @param clientRegistrationRepository
     * @param addonsProperties
     * @return {@link SpringAddonsLogoutSuccessHandler}
     */
    @ConditionalOnMissingBean
    @Bean
    LogoutSuccessHandler logoutSuccessHandler(
            LogoutRequestUriBuilder logoutRequestUriBuilder,
            ClientRegistrationRepository clientRegistrationRepository,
            SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsLogoutSuccessHandler(logoutRequestUriBuilder, clientRegistrationRepository, addonsProperties);
    }

    /**
     * @return a Post processor for access control in Java configuration which requires users to be authenticated. It is called after "permit-all" configuration
     *         property was applied.
     */
    @ConditionalOnMissingBean
    @Bean
    ClientExpressionInterceptUrlRegistryPostProcessor clientAuthorizePostProcessor() {
        return registry -> registry.anyRequest().authenticated();
    }

    /**
     * @return a no-op post processor
     */
    @ConditionalOnMissingBean
    @Bean
    ClientHttpSecurityPostProcessor clientHttpPostProcessor() {
        return http -> http;
    }

    @ConditionalOnMissingBean
    @Bean
    PreAuthorizationCodeRedirectStrategy authorizationCodeRedirectStrategy(SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsPreAuthorizationCodeRedirectStrategy(addonsProperties.getClient().getOauth2Redirections().getPreAuthorizationCode());
    }

    static class SpringAddonsPreAuthorizationCodeRedirectStrategy extends SpringAddonsOauth2RedirectStrategy implements PreAuthorizationCodeRedirectStrategy {
        public SpringAddonsPreAuthorizationCodeRedirectStrategy(HttpStatus defaultStatus) {
            super(defaultStatus);
        }
    }

    @Conditional(DefaultAuthenticationSuccessHandlerCondition.class)
    @Bean
    AuthenticationSuccessHandler authenticationSuccessHandler(SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsOauth2AuthenticationSuccessHandler(addonsProperties);
    }

    @Conditional(DefaultAuthenticationFailureHandlerCondition.class)
    @Bean
    AuthenticationFailureHandler authenticationFailureHandler(SpringAddonsOidcProperties addonsProperties) {
        return new SpringAddonsOauth2AuthenticationFailureHandler(addonsProperties);
    }
}
