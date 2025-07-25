package com.c4_soft.springaddons.security.oidc.starter.synchronised.client;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OidcBackChannelLogoutHandler;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.util.UriComponentsBuilder;
import com.c4_soft.springaddons.security.oidc.starter.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oidc.starter.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationEntryPointCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationFailureHandlerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationSuccessHandlerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultCorsFilterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOidcBackChannelLogoutHandlerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOidcSessionRegistryCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsClientWithLoginCondition;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.ServletConfigurationSupport;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.SpringAddonsOidcBeans;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * The following {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBeans} are auto-configured
 * <ul>
 * <li>springAddonsClientFilterChain: a {@link SecurityFilterChain}. Instantiated only if
 * "com.c4-soft.springaddons.oidc.client.security-matchers" property has at least one entry. If
 * defined, it is with highest precedence, to ensure that all routes defined in this security
 * matcher property are intercepted by this filter-chain.</li>
 * <li>oAuth2AuthorizationRequestResolver: a {@link OAuth2AuthorizationRequestResolver}. Default
 * instance is a {@link SpringAddonsOAuth2AuthorizationRequestResolver} which sets the client
 * hostname in the redirect URI with {@link SpringAddonsOidcClientProperties#clientUri
 * SpringAddonsOidcClientProperties#client-uri}</li>
 * <li>logoutRequestUriBuilder: builder for
 * <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a>
 * queries, taking configuration from properties for OIDC providers which do not strictly comply
 * with the spec: logout URI not provided by OIDC conf or non standard parameter names (Auth0 and
 * Cognito are samples of such OPs)</li>
 * <li>logoutSuccessHandler: a {@link LogoutSuccessHandler}. Default instance is a
 * {@link SpringAddonsLogoutSuccessHandler} which logs a user out from the last authorization server
 * he logged on.</li>
 * <li>authoritiesConverter: an {@link ClaimSetAuthoritiesConverter}. Default instance is a
 * {@link ConfigurableClaimSetAuthoritiesConverter} which reads spring-addons
 * {@link SpringAddonsOidcProperties}</li>
 * <li>clientAuthorizePostProcessor: a {@link ClientExpressionInterceptUrlRegistryPostProcessor}
 * post processor to fine tune access control from java configuration. It applies to all routes not
 * listed in "permit-all" property configuration. Default requires users to be authenticated.</li>
 * <li>clientHttpPostProcessor: a {@link ClientSynchronizedHttpSecurityPostProcessor} to override
 * anything from above auto-configuration. It is called just before the security filter-chain is
 * returned. Default is a no-op.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnWebApplication(type = Type.SERVLET)
@Conditional(IsClientWithLoginCondition.class)
@EnableWebSecurity
@AutoConfiguration
@ImportAutoConfiguration(SpringAddonsOidcBeans.class)
@Slf4j
public class SpringAddonsOidcClientWithLoginBeans {

  /**
   * <p>
   * Instantiated only if "com.c4-soft.springaddons.oidc.client.security-matchers" property has at
   * least one entry. If defined, it is with higher precedence than resource server one.
   * </p>
   * It defines:
   * <ul>
   * <li>If the path to login page was provided in conf, a &#64;Controller must be provided to
   * handle it. Otherwise Spring Boot default generated one is used (be aware that it does not work
   * when bound to 80 or 8080 with SSL enabled, so, in that case, use another port or define a login
   * path and a controller to handle it)</li>
   * <li>logout (using {@link SpringAddonsLogoutSuccessHandler} by default)</li>
   * <li>forces SSL usage if it is enabled</li> properties</li>
   * <li>CSRF protection as defined in spring-addons <b>client</b> properties (enabled by default in
   * this filter-chain).</li>
   * <li>allow access to unauthorized requests to path matchers listed in spring-security
   * <b>client</b> "permit-all" property</li>
   * <li>as usual, apply {@link ClientExpressionInterceptUrlRegistryPostProcessor} for access
   * control configuration from Java conf and {@link ClientSynchronizedHttpSecurityPostProcessor} to
   * override anything from the auto-configuration listed above</li>
   * </ul>
   *
   * @param http the security filter-chain builder to configure
   * @param serverProperties Spring Boot standard server properties
   * @param authorizationRequestResolver the authorization request resolver to use. By default
   *        {@link SpringAddonsOAuth2AuthorizationRequestResolver} (adds authorization request
   *        parameters defined in properties and builds absolutes callback URI)
   * @param preAuthorizationCodeRedirectStrategy the redirection strategy to use for
   *        authorization-code request
   * @param authenticationEntryPoint the {@link AuthenticationEntryPoint} to use. Default is
   *        {@link SpringAddonsAuthenticationEntryPoint}
   * @param authenticationSuccessHandler the authentication success handler to use. Default is a
   *        {@link SpringAddonsOauth2AuthenticationSuccessHandler}
   * @param authenticationFailureHandler the authentication failure handler to use. Default is a
   *        {@link SpringAddonsOauth2AuthenticationFailureHandler}
   * @param invalidSessionStrategy default redirects to login, unless another status is set in
   *        com.c4-soft.springaddons.oidc.client.oauth2-redirections.invalid-session-strategy
   * @param logoutSuccessHandler Defaulted to {@link SpringAddonsLogoutSuccessHandler} which can
   *        handle "almost" RP Initiated Logout conformant OPs (like Auth0 and Cognito). Default is
   *        a {@link SpringAddonsLogoutSuccessHandler}
   * @param addonsProperties {@link SpringAddonsOAuth2ClientProperties spring-addons client
   *        properties}
   * @param authorizePostProcessor post process authorization after "permit-all" configuration was
   *        applied (default is "isAuthenticated()" to everything that was not matched)
   * @param httpPostProcessor post process the "http" builder just before it is returned (enables to
   *        override anything from the auto-configuration) spring-addons client properties}
   * @param oidcBackChannelLogoutHandler if present, Back-Channel Logout is enabled. A default
   *        {@link OidcBackChannelLogoutHandler} is provided if
   *        com.c4-soft.springaddons.oidc.client.back-channel-logout.enabled is true
   * @return a security filter-chain scoped to specified security-matchers and adapted to OAuth2
   *         clients
   * @throws Exception in case of miss-configuration
   */
  @Order(Ordered.LOWEST_PRECEDENCE - 1)
  @Bean
  SecurityFilterChain springAddonsClientFilterChain(HttpSecurity http,
      ServerProperties serverProperties,
      PreAuthorizationCodeRedirectStrategy preAuthorizationCodeRedirectStrategy,
      OAuth2AuthorizationRequestResolver authorizationRequestResolver,
      AuthenticationEntryPoint authenticationEntryPoint,
      AuthenticationSuccessHandler authenticationSuccessHandler,
      AuthenticationFailureHandler authenticationFailureHandler,
      InvalidSessionStrategy invalidSessionStrategy, Optional<LogoutHandler> logoutHandler,
      LogoutSuccessHandler logoutSuccessHandler, SpringAddonsOidcProperties addonsProperties,
      ClientExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
      ClientSynchronizedHttpSecurityPostProcessor httpPostProcessor,
      Optional<OidcBackChannelLogoutHandler> oidcBackChannelLogoutHandler) throws Exception {
    // @formatter:off
        log.info("Applying client OAuth2 configuration for: {}", addonsProperties.getClient().getSecurityMatchers());
        http.securityMatcher(addonsProperties.getClient().getSecurityMatchers().toArray(new String[] {}));

    	http.sessionManagement(sessions -> {
    		sessions.invalidSessionStrategy(invalidSessionStrategy);
		});
        
        http.exceptionHandling(exceptions -> {
        	exceptions.authenticationEntryPoint(authenticationEntryPoint);
        });

        http.oauth2Login(login -> {
        	login.authorizationEndpoint(authorizationEndpoint -> {
        		authorizationEndpoint.authorizationRedirectStrategy(preAuthorizationCodeRedirectStrategy);
        		authorizationEndpoint.authorizationRequestResolver(authorizationRequestResolver);
        	});
            login.successHandler(authenticationSuccessHandler);
            login.failureHandler(authenticationFailureHandler);
        });

        http.logout(logout -> {
            logout.logoutSuccessHandler(logoutSuccessHandler);
        });
        // @formatter:on

    if (oidcBackChannelLogoutHandler.isPresent()) {
      http.oidcLogout(
          ol -> ol.backChannel(bc -> bc.logoutHandler(oidcBackChannelLogoutHandler.get())));
    }

    ServletConfigurationSupport.configureClient(http, serverProperties, addonsProperties,
        authorizePostProcessor, httpPostProcessor);

    return http.build();
  }

  /**
   * Use a {@link SpringAddonsOAuth2AuthorizationRequestResolver} which:
   * <ul>
   * <li>takes hostname and port from configuration properties (and works even if SSL is enabled on
   * port 8080)</li>
   * <li>spport defining additionl authorization request parameters from properties</li>
   * </ul>
   *
   * @param bootClientProperties "standard" Spring Boot OAuth2 client properties
   * @param clientRegistrationRepository
   * @param addonsProperties "spring-addons" OAuth2 client properties
   * @return {@link SpringAddonsOAuth2AuthorizationRequestResolver}
   */
  @ConditionalOnMissingBean
  @Bean
  OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(
      OAuth2ClientProperties bootClientProperties,
      ClientRegistrationRepository clientRegistrationRepository,
      SpringAddonsOidcProperties addonsProperties) {
    return new SpringAddonsOAuth2AuthorizationRequestResolver(bootClientProperties,
        clientRegistrationRepository, addonsProperties.getClient());
  }

  /**
   * Build logout request for
   * <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
   * Logout</a>. It works with most OIDC provider: those complying with the spec (Keycloak for
   * instance), off course, but also those which are close enough to it (Auth0, Cognito, ...)
   *
   * @param addonsProperties {@link SpringAddonsOAuth2ClientProperties} to pick logout configuration
   *        for divergence to the standard (logout URI not provided in
   *        .well-known/openid-configuration and non-conform parameter names)
   * @return {@link SpringAddonsOAuth2LogoutRequestUriBuilder]
   */
  @ConditionalOnMissingBean
  @Bean
  LogoutRequestUriBuilder logoutRequestUriBuilder(SpringAddonsOidcProperties addonsProperties) {
    return new SpringAddonsOAuth2LogoutRequestUriBuilder(addonsProperties.getClient());
  }

  /**
   * Single tenant logout handler for OIDC provider complying to
   * <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a>
   * (or approximately complying to it like Auth0 or Cognito)
   *
   * @param logoutRequestUriBuilder delegate doing the smart job
   * @param clientRegistrationRepository
   * @param addonsProperties
   * @return {@link SpringAddonsLogoutSuccessHandler}
   */
  @ConditionalOnMissingBean
  @Bean
  LogoutSuccessHandler logoutSuccessHandler(LogoutRequestUriBuilder logoutRequestUriBuilder,
      ClientRegistrationRepository clientRegistrationRepository,
      SpringAddonsOidcProperties addonsProperties) {
    return new SpringAddonsLogoutSuccessHandler(logoutRequestUriBuilder,
        clientRegistrationRepository, addonsProperties);
  }

  /**
   * @return a Post processor for access control in Java configuration which requires users to be
   *         authenticated. It is called after "permit-all" configuration property was applied.
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
  ClientSynchronizedHttpSecurityPostProcessor clientHttpPostProcessor() {
    return http -> http;
  }

  @ConditionalOnMissingBean
  @Bean
  PreAuthorizationCodeRedirectStrategy authorizationCodeRedirectStrategy(
      SpringAddonsOidcProperties addonsProperties) {
    return new SpringAddonsPreAuthorizationCodeRedirectStrategy(
        addonsProperties.getClient().getOauth2Redirections().getPreAuthorizationCode());
  }

  public static class SpringAddonsPreAuthorizationCodeRedirectStrategy
      extends SpringAddonsOauth2RedirectStrategy implements PreAuthorizationCodeRedirectStrategy {
    public SpringAddonsPreAuthorizationCodeRedirectStrategy(HttpStatus defaultStatus) {
      super(defaultStatus);
    }
  }

  @ConditionalOnMissingBean(InvalidSessionStrategy.class)
  @Bean
  InvalidSessionStrategy invalidSessionStrategy(ServerProperties serverProperties,
      SpringAddonsOidcProperties addonsProperties) {
    return (HttpServletRequest request, HttpServletResponse response) -> {
      final var location = addonsProperties.getClient().getInvalidSession().getLocation()
          .map(URI::toString).orElseGet(() -> {
            final var requestUri = URI.create(request.getRequestURI());
            if (StringUtils.hasText(requestUri.getHost())) {
              return requestUri.toString();
            }
            final var segments = Arrays.stream(requestUri.getPath().split("/"))
                .filter(StringUtils::hasText).toArray(String[]::new);
            final var clientUri =
                addonsProperties.getClient().getClientUri().orElseGet(() -> URI.create(Optional
                    .ofNullable(serverProperties.getServlet().getContextPath()).orElse("/")));
            return UriComponentsBuilder.fromUri(clientUri).pathSegment(segments).build().toString();
          });
      log.debug("Invalid session. Returning with status %d and %s as location".formatted(
          addonsProperties.getClient().getInvalidSession().getStatus().value(), location));
      response.setStatus(addonsProperties.getClient().getInvalidSession().getStatus().value());
      response.setHeader(HttpHeaders.LOCATION, location);
      if (addonsProperties.getClient().getInvalidSession().getStatus().is4xxClientError()
          || addonsProperties.getClient().getInvalidSession().getStatus().is5xxServerError()) {
        response.getOutputStream().write("Invalid session. Please authenticate.".getBytes());
      }
      response.flushBuffer();
    };
  }

  @Conditional(DefaultAuthenticationEntryPointCondition.class)
  @Bean
  AuthenticationEntryPoint authenticationEntryPoint(SpringAddonsOidcProperties addonsProperties) {
    return new SpringAddonsAuthenticationEntryPoint(addonsProperties.getClient());
  }

  @Conditional(DefaultAuthenticationSuccessHandlerCondition.class)
  @Bean
  AuthenticationSuccessHandler authenticationSuccessHandler(
      SpringAddonsOidcProperties addonsProperties) {
    return new SpringAddonsOauth2AuthenticationSuccessHandler(addonsProperties);
  }

  @Conditional(DefaultAuthenticationFailureHandlerCondition.class)
  @Bean
  AuthenticationFailureHandler authenticationFailureHandler(
      SpringAddonsOidcProperties addonsProperties) {
    return new SpringAddonsOauth2AuthenticationFailureHandler(addonsProperties);
  }

  @Conditional(DefaultCorsFilterCondition.class)
  @Bean
  CorsFilter corsFilter(SpringAddonsOidcProperties addonsProperties) {
    final var corsProps = new ArrayList<>(addonsProperties.getCors());

    return ServletConfigurationSupport.getCorsFilterBean(corsProps);
  }

  @Conditional(DefaultOidcSessionRegistryCondition.class)
  @Bean
  OidcSessionRegistry oidcSessionRegistry() {
    return new InMemoryOidcSessionRegistry();
  }

  @Conditional(DefaultOidcBackChannelLogoutHandlerCondition.class)
  @Bean
  OidcBackChannelLogoutHandler oidcBackChannelLogoutHandler(OidcSessionRegistry sessionRegistry,
      SpringAddonsOidcProperties addonsProperties) {
    OidcBackChannelLogoutHandler logoutHandler = new OidcBackChannelLogoutHandler(sessionRegistry);
    addonsProperties.getClient().getBackChannelLogout().getInternalLogoutUri()
        .ifPresent(logoutHandler::setLogoutUri);
    addonsProperties.getClient().getBackChannelLogout().getCookieName()
        .ifPresent(logoutHandler::setSessionCookieName);
    return logoutHandler;
  }

}
