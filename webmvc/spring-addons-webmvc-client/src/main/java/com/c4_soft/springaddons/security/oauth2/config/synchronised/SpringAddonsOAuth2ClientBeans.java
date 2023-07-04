package com.c4_soft.springaddons.security.oauth2.config.synchronised;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.UriComponentsBuilder;

import com.c4_soft.springaddons.security.oauth2.config.ClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.ConfigurableClaimSetAuthoritiesConverter;
import com.c4_soft.springaddons.security.oauth2.config.LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2ClientProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsOAuth2LogoutRequestUriBuilder;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties.CorsProperties;

import lombok.extern.slf4j.Slf4j;

/**
 * The following {@link ConditionalOnMissingBean &#64;ConditionalOnMissingBeans} are auto-configured
 * <ul>
 * <li>springAddonsClientFilterChain: a {@link SecurityFilterChain}. Instantiated only if "com.c4-soft.springaddons.security.client.security-matchers" property
 * has at least one entry. If defined, it is with highest precedence, to ensure that all routes defined in this security matcher property are intercepted by
 * this filter-chain.</li>
 * <li>oAuth2AuthorizationRequestResolver: a {@link OAuth2AuthorizationRequestResolver}. Default instance is a
 * {@link SpringAddonsOAuth2AuthorizationRequestResolver} which sets the client hostname in the redirect URI with
 * {@link SpringAddonsOAuth2ClientProperties#getClientUri() SpringAddonsOAuth2ClientProperties#client-uri}</li>
 * <li>logoutRequestUriBuilder: builder for <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a> queries, taking
 * configuration from properties for OIDC providers which do not strictly comply with the spec: logout URI not provided by OIDC conf or non standard parameter
 * names (Auth0 and Cognito are samples of such OPs)</li>
 * <li>logoutSuccessHandler: a {@link LogoutSuccessHandler}. Default instance is a {@link SpringAddonsOAuth2LogoutSuccessHandler} which logs a user out from the
 * last authorization server he logged on.</li>
 * <li>authoritiesConverter: an {@link ClaimSetAuthoritiesConverter}. Default instance is a {@link ConfigurableClaimSetAuthoritiesConverter} which reads
 * spring-addons {@link SpringAddonsSecurityProperties}</li>
 * <li>oAuth2AuthorizedClientRepository: a {@link SpringAddonsOAuth2AuthorizedClientRepository} (which is also a session listener) capable of handling
 * multi-tenancy and back-channel logout.</li>
 * <li>clientAuthorizePostProcessor: a {@link ClientExpressionInterceptUrlRegistryPostProcessor} post processor to fine tune access control from java
 * configuration. It applies to all routes not listed in "permit-all" property configuration. Default requires users to be authenticated.</li>
 * <li>clientHttpPostProcessor: a {@link ClientHttpSecurityPostProcessor} to override anything from above auto-configuration. It is called just before the
 * security filter-chain is returned. Default is a no-op.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnProperty(matchIfMissing = true, prefix = "com.c4-soft.springaddons.security.client", name = "enabled")
@EnableWebSecurity
@AutoConfiguration
@Import({ SpringAddonsOAuth2ClientProperties.class })
@Slf4j
public class SpringAddonsOAuth2ClientBeans {

	/**
	 * <p>
	 * Instantiated only if "com.c4-soft.springaddons.security.client.security-matchers" property has at least one entry. If defined, it is with highest
	 * precedence, to ensure that all routes defined in this security matcher property are intercepted by this filter-chain.
	 * </p>
	 * It defines:
	 * <ul>
	 * <li>If the path to login page was provided in conf, a &#64;Controller must be provided to handle it. Otherwise Spring Boot default generated one is used
	 * (be aware that it does not work when bound to 80 or 8080 with SSL enabled, so, in that case, use another port or define a login path and a controller to
	 * handle it)</li>
	 * <li>logout (using {@link SpringAddonsOAuth2LogoutSuccessHandler} by default)</li>
	 * <li>forces SSL usage if it is enabled</li> properties</li>
	 * <li>CSRF protection as defined in spring-addons <b>client</b> properties (enabled by default in this filter-chain).</li>
	 * <li>allow access to unauthorized requests to path matchers listed in spring-security <b>client</b> "permit-all" property</li>
	 * <li>as usual, apply {@link ClientExpressionInterceptUrlRegistryPostProcessor} for access control configuration from Java conf and
	 * {@link ClientHttpSecurityPostProcessor} to override anything from the auto-configuration listed above</li>
	 * </ul>
	 *
	 * @param  http                         the security filter-chain builder to configure
	 * @param  serverProperties             Spring Boot standard server properties
	 * @param  authorizationRequestResolver the authorization request resolver to use. By default {@link SpringAddonsOAuth2AuthorizationRequestResolver} (adds
	 *                                      authorization request parameters defined in properties and builds absolutes callback URI)
	 * @param  clientProps                  {@link SpringAddonsOAuth2ClientProperties spring-addons client properties}
	 * @param  authorizePostProcessor       post process authorization after "permit-all" configuration was applied (default is "isAuthenticated()" to
	 *                                      everything that was not matched)
	 * @param  httpPostProcessor            post process the "http" builder just before it is returned (enables to override anything from the
	 *                                      auto-configuration) spring-addons client properties}
	 * @return                              a security filter-chain scoped to specified security-matchers and adapted to OAuth2 clients
	 * @throws Exception                    in case of miss-configuration
	 */
	@ConditionalOnExpression("!(T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers:}') && T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers[0]:}'))")
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	@Bean
	SecurityFilterChain springAddonsClientFilterChain(
			HttpSecurity http,
			ServerProperties serverProperties,
			OAuth2AuthorizationRequestResolver authorizationRequestResolver,
			LogoutSuccessHandler logoutSuccessHandler,
			SpringAddonsOAuth2ClientProperties clientProps,
			ClientExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
			ClientHttpSecurityPostProcessor httpPostProcessor)
			throws Exception {
		// @formatter:off
        log.info("Applying client OAuth2 configuration for: {}", (Object[]) clientProps.getSecurityMatchers());
        http.securityMatcher(clientProps.getSecurityMatchers());

        http.oauth2Login(login -> {
        	login.authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint.authorizationRequestResolver(authorizationRequestResolver));
            clientProps.getLoginPath().ifPresent(loginPath -> {
                login.loginPage(UriComponentsBuilder.fromUri(clientProps.getClientUri()).path(loginPath).build().toString());
            });
            clientProps.getPostLoginRedirectPath().ifPresent(postLoginRedirectPath -> {
                login.defaultSuccessUrl(UriComponentsBuilder.fromUri(clientProps.getClientUri()).path(postLoginRedirectPath).build().toString(), true);
            });
        });

        http.logout(logout -> {
            logout.logoutSuccessHandler(logoutSuccessHandler);
        });
        // @formatter:on

		ServletConfigurationSupport.configureClient(http, serverProperties, clientProps, authorizePostProcessor, httpPostProcessor);

		return http.build();
	}

	/**
	 * Use a {@link SpringAddonsOAuth2AuthorizationRequestResolver} which:
	 * <ul>
	 * <li>takes hostname and port from configuration properties (and works even if SSL is enabled on port 8080)</li>
	 * <li>spport defining additionl authorization request parameters from properties</li>
	 * </ul>
	 *
	 * @param  clientRegistrationRepository
	 * @param  clientProps
	 * @return                              {@link SpringAddonsOAuth2AuthorizationRequestResolver}
	 */
	@ConditionalOnMissingBean
	@Bean
	OAuth2AuthorizationRequestResolver oAuth2AuthorizationRequestResolver(
			InMemoryClientRegistrationRepository clientRegistrationRepository,
			SpringAddonsOAuth2ClientProperties clientProps) {
		return new SpringAddonsOAuth2AuthorizationRequestResolver(clientRegistrationRepository, clientProps);
	}

	/**
	 * Build logout request for <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated Logout</a>. It works with most OIDC
	 * provider: those complying with the spec (Keycloak for instance), off course, but also those which are close enough to it (Auth0, Cognito, ...)
	 *
	 * @param  clientProps {@link SpringAddonsOAuth2ClientProperties} to pick logout configuration for divergence to the standard (logout URI not provided in
	 *                     .well-known/openid-configuration and non-conform parameter names)
	 * @return             {@link SpringAddonsOAuth2LogoutRequestUriBuilder]
	 */
	@ConditionalOnMissingBean
	@Bean
	LogoutRequestUriBuilder logoutRequestUriBuilder(SpringAddonsOAuth2ClientProperties clientProps) {
		return new SpringAddonsOAuth2LogoutRequestUriBuilder(clientProps);
	}

	/**
	 * Single tenant logout handler for OIDC provider complying to <a href= "https://openid.net/specs/openid-connect-rpinitiated-1_0.html">RP-Initiated
	 * Logout</a> (or approximately complying to it like Auth0 or Cognito)
	 *
	 * @param  logoutRequestUriBuilder      delegate doing the smart job
	 * @param  clientRegistrationRepository
	 * @return                              {@link SpringAddonsOAuth2LogoutSuccessHandler}
	 */
	@ConditionalOnMissingBean
	@Bean
	LogoutSuccessHandler logoutSuccessHandler(LogoutRequestUriBuilder logoutRequestUriBuilder, ClientRegistrationRepository clientRegistrationRepository) {
		return new SpringAddonsOAuth2LogoutSuccessHandler(logoutRequestUriBuilder, clientRegistrationRepository);
	}

	/**
	 * Instantiate a {@link ConfigurableClaimSetAuthoritiesConverter} from token claims to spring authorities (which claims to pick, how to transform roles
	 * strings for each claim).
	 *
	 * @param  addonsProperties converter configuration source
	 * @return                  {@link ConfigurableClaimSetAuthoritiesConverter}
	 */
	@ConditionalOnMissingBean
	@Bean
	ClaimSetAuthoritiesConverter authoritiesConverter(SpringAddonsSecurityProperties addonsProperties) {
		return new ConfigurableClaimSetAuthoritiesConverter(addonsProperties);
	}

	/**
	 * @param  authoritiesConverter the authorities converter to use (by default {@link ConfigurableClaimSetAuthoritiesConverter})
	 * @return                      {@link GrantedAuthoritiesMapper} using the authorities converter in the context
	 */
	@ConditionalOnMissingBean
	@Bean
	GrantedAuthoritiesMapper grantedAuthoritiesMapper(Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter) {
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
	 * @param  corsProperties the properties to pick CORS configuration from
	 * @return                a CORS configuration built from properties
	 */
	CorsConfigurationSource corsConfig(CorsProperties[] corsProperties) {
		log.debug("Building default CorsConfigurationSource with: {}", Stream.of(corsProperties).toList());
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
	 * @param  clientRegistrationRepository the OIDC providers configuration
	 * @return                              {@link SpringAddonsOAuth2AuthorizedClientRepository}, an authorized client repository supporting multi-tenancy and
	 *                                      exposing the required API for back-channel logout
	 */
	@ConditionalOnMissingBean
	@Bean
	SpringAddonsOAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository(ClientRegistrationRepository clientRegistrationRepository) {
		return new SpringAddonsOAuth2AuthorizedClientRepository(clientRegistrationRepository);
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

	static class HasClientSecurityMatcher extends AnyNestedCondition {

		public HasClientSecurityMatcher() {
			super(ConfigurationPhase.PARSE_CONFIGURATION);
		}

		@ConditionalOnExpression("!(T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers:}') && T(org.springframework.util.StringUtils).isEmpty('${com.c4-soft.springaddons.security.client.security-matchers[0]:}'))")
		static class Value1Condition {

		}

		@ConditionalOnProperty(name = "com.c4-soft.springaddons.security.client.security-matchers[0]")
		static class Value2Condition {

		}

	}
}