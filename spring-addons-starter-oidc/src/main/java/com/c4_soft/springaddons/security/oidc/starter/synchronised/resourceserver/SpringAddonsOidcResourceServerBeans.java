
package com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.web.server.autoconfigure.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.filter.CorsFilter;
import com.c4_soft.springaddons.security.oidc.OpenidClaimSet;
import com.c4_soft.springaddons.security.oidc.starter.OpenidProviderPropertiesResolver;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultAuthenticationManagerResolverCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultCorsFilterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultJwtAbstractAuthenticationTokenConverterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.DefaultOpaqueTokenAuthenticationConverterCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.IsIntrospectingResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.bean.IsJwtDecoderResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.properties.condition.configuration.IsOidcResourceServerCondition;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.ServletConfigurationSupport;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.SpringAddonsOidcBeans;
import jakarta.servlet.http.HttpServletRequest;

/**
 * <p>
 * <b>Usage</b><br>
 * If not using spring-boot, &#64;Import or &#64;ComponentScan this class. All beans defined here
 * are &#64;ConditionalOnMissingBean =&gt; just define your own &#64;Beans to override.
 * </p>
 * <p>
 * <b>Provided &#64;Beans</b>
 * </p>
 * <ul>
 * <li>springAddonsResourceServerSecurityFilterChain: applies CORS, CSRF, anonymous,
 * sessionCreationPolicy, SSL, redirect and 401 instead of redirect to login as defined in <a href=
 * "https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-oauth2/src/main/java/com/c4_soft/springaddons/security/oauth2/config/SpringAddonsSecurityProperties.java">SpringAddonsSecurityProperties</a></li>
 * <li>authorizePostProcessor: a bean of type
 * {@link ResourceServerExpressionInterceptUrlRegistryPostProcessor} to fine tune access control
 * from java configuration. It applies to all routes not listed in "permit-all" property
 * configuration. Default requires users to be authenticated. <b>This is a bean to provide in your
 * application configuration if you prefer to define fine-grained access control rules with Java
 * configuration rather than methods security.</b></li>
 * <li>httpPostProcessor: a bean of type {@link ResourceServerSynchronizedHttpSecurityPostProcessor}
 * to override anything from above auto-configuration. It is called just before the security
 * filter-chain is returned. Default is a no-op.</li>
 * <li>jwtAuthenticationConverter: a converter from a {@link Jwt} to something inheriting from
 * {@link AbstractAuthenticationToken}. The default instantiate a {@link JwtAuthenticationToken}
 * with username and authorities as configured for the issuer of thi token. The easiest to override
 * the type of {@link AbstractAuthenticationToken}, is to provide with an Converter&lt;Jwt, ?
 * extends AbstractAuthenticationToken&gt; bean.</li>
 * <li>authenticationManagerResolver: to accept authorities from more than one issuer, the
 * recommended way is to provide an {@link AuthenticationManagerResolver<HttpServletRequest>}
 * supporting it. Default keeps a {@link JwtAuthenticationProvider} with its own {@link JwtDecoder}
 * for each issuer.</li>
 * </ul>
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
@ConditionalOnWebApplication(type = Type.SERVLET)
@Conditional(IsOidcResourceServerCondition.class)
@EnableWebSecurity
@AutoConfiguration
@ImportAutoConfiguration(SpringAddonsOidcBeans.class)
public class SpringAddonsOidcResourceServerBeans {
  /**
   * <p>
   * Configures a SecurityFilterChain for a resource server with JwtDecoder with
   * &#64;Order(LOWEST_PRECEDENCE). Defining a {@link SecurityWebFilterChain} bean with no security
   * matcher and an order higher than LOWEST_PRECEDENCE will hide this filter-chain an disable most
   * of spring-addons auto-configuration for OpenID resource-servers.
   * </p>
   *
   * @param http HTTP security to configure
   * @param serverProperties Spring "server" configuration properties
   * @param addonsProperties "com.c4-soft.springaddons.oidc" configuration properties
   * @param authorizePostProcessor Hook to override access-control rules for all path that are not
   *        listed in "permit-all"
   * @param httpPostProcessor Hook to override all or part of HttpSecurity auto-configuration
   * @param authenticationManagerResolver Converts successful JWT decoding result into an
   *        {@link Authentication}
   * @return A {@link SecurityWebFilterChain} for servlet resource-servers with JWT decoder
   */
  @Conditional(IsJwtDecoderResourceServerCondition.class)
  @Order(Ordered.LOWEST_PRECEDENCE)
  @Bean
  SecurityFilterChain springAddonsJwtResourceServerSecurityFilterChain(HttpSecurity http,
      ServerProperties serverProperties, SpringAddonsOidcProperties addonsProperties,
      ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
      ResourceServerSynchronizedHttpSecurityPostProcessor httpPostProcessor,
      AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver)
      throws Exception {
    http.oauth2ResourceServer(oauth2 -> {
      oauth2.authenticationManagerResolver(authenticationManagerResolver);
    });

    ServletConfigurationSupport.configureResourceServer(http, serverProperties, addonsProperties,
        authorizePostProcessor, httpPostProcessor);

    return http.build();
  }

  /**
   * <p>
   * Configures a SecurityFilterChain for a resource server with JwtDecoder with
   * &#64;Order(LOWEST_PRECEDENCE). Defining a {@link SecurityWebFilterChain} bean with no security
   * matcher and an order higher than LOWEST_PRECEDENCE will hide this filter-chain an disable most
   * of spring-addons auto-configuration for OpenID resource-servers.
   * </p>
   *
   * @param http HTTP security to configure
   * @param serverProperties Spring "server" configuration properties
   * @param addonsProperties "com.c4-soft.springaddons.oidc" configuration properties
   * @param authorizePostProcessor Hook to override access-control rules for all path that are not
   *        listed in "permit-all"
   * @param httpPostProcessor Hook to override all or part of HttpSecurity auto-configuration
   * @param introspectionAuthenticationConverter Converts successful introspection result into an
   *        {@link Authentication}
   * @param opaqueTokenIntrospector the instrospector to use
   * @return A {@link SecurityWebFilterChain} for servlet resource-servers with access token
   *         introspection
   */
  @Conditional(IsIntrospectingResourceServerCondition.class)
  @Order(Ordered.LOWEST_PRECEDENCE)
  @Bean
  SecurityFilterChain springAddonsIntrospectingResourceServerSecurityFilterChain(HttpSecurity http,
      ServerProperties serverProperties, SpringAddonsOidcProperties addonsProperties,
      ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
      ResourceServerSynchronizedHttpSecurityPostProcessor httpPostProcessor,
      OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter,
      OpaqueTokenIntrospector opaqueTokenIntrospector) throws Exception {
    http.oauth2ResourceServer(server -> server.opaqueToken(ot -> {
      ot.introspector(opaqueTokenIntrospector);
      ot.authenticationConverter(introspectionAuthenticationConverter);
    }));

    ServletConfigurationSupport.configureResourceServer(http, serverProperties, addonsProperties,
        authorizePostProcessor, httpPostProcessor);

    return http.build();
  }

  /**
   * hook to override security rules for all path that are not listed in "permit-all". Default is
   * isAuthenticated().
   *
   * @return a hook to override security rules for all path that are not listed in "permit-all".
   *         Default is isAuthenticated().
   */
  @ConditionalOnMissingBean
  @Bean
  ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor() {
    return registry -> registry.anyRequest().authenticated();
  }

  /**
   * Hook to override all or part of HttpSecurity auto-configuration. Called after spring-addons
   * configuration was applied so that you can modify anything
   *
   * @return a hook to override all or part of HttpSecurity auto-configuration. Called after
   *         spring-addons configuration was applied so that you can modify anything
   */
  @ConditionalOnMissingBean
  @Bean
  ResourceServerSynchronizedHttpSecurityPostProcessor httpPostProcessor() {
    return httpSecurity -> httpSecurity;
  }

  @ConditionalOnMissingBean
  @Bean
  SpringAddonsJwtDecoderFactory springAddonsJwtDecoderFactory() {
    return new DefaultSpringAddonsJwtDecoderFactory();
  }

  /**
   * Provides with multi-tenancy: builds a AuthenticationManagerResolver<HttpServletRequest> per
   * provided OIDC issuer URI
   *
   * @param opPropertiesResolver a resolver for OpenID Provider configuration properties
   * @param jwtDecoderFactory something to build a JWT decoder from OpenID Provider configuration
   *        properties
   * @param jwtAuthenticationConverter converts from a {@link Jwt} to an {@link Authentication}
   *        implementation
   * @return Multi-tenant {@link AuthenticationManagerResolver<HttpServletRequest>} (one for each
   *         configured issuer)
   */
  @Conditional(DefaultAuthenticationManagerResolverCondition.class)
  @Bean
  AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver(
      OpenidProviderPropertiesResolver opPropertiesResolver,
      SpringAddonsJwtDecoderFactory jwtDecoderFactory,
      Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter) {
    return new SpringAddonsJwtAuthenticationManagerResolver(opPropertiesResolver, jwtDecoderFactory,
        jwtAuthenticationConverter);
  }

  /**
   * Converter bean from {@link Jwt} to {@link AbstractAuthenticationToken}
   *
   * @param authoritiesConverter converts access-token claims into Spring authorities
   * @param opPropertiesResolver spring-addons configuration properties
   * @return a converter from {@link Jwt} to {@link AbstractAuthenticationToken}
   */
  @Conditional(DefaultJwtAbstractAuthenticationTokenConverterCondition.class)
  @Bean
  JwtAbstractAuthenticationTokenConverter jwtAuthenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
      OpenidProviderPropertiesResolver opPropertiesResolver) {
    return jwt -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt.getClaims()),
        new OpenidClaimSet(jwt.getClaims(),
            opPropertiesResolver.resolve(jwt.getClaims())
                .orElseThrow(() -> new NotAConfiguredOpenidProviderException(jwt.getClaims()))
                .getUsernameClaim()).getName());
  }

  /**
   * Converter bean from successful introspection result to an {@link Authentication} instance
   *
   * @param authoritiesConverter converts access-token claims into Spring authorities
   * @param addonsProperties spring-addons configuration properties
   * @param resourceServerProperties Spring Boot standard resource server configuration properties
   * @return a converter from successful introspection result to an {@link Authentication} instance
   */
  @Conditional(DefaultOpaqueTokenAuthenticationConverterCondition.class)
  @Bean
  @SuppressWarnings("unchecked")
  OpaqueTokenAuthenticationConverter introspectionAuthenticationConverter(
      Converter<Map<String, Object>, Collection<? extends GrantedAuthority>> authoritiesConverter,
      SpringAddonsOidcProperties addonsProperties,
      OAuth2ResourceServerProperties resourceServerProperties) {
    return (String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) -> {
      final var iatClaim =
          authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT);
      final var expClaim =
          authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP);
      return new BearerTokenAuthentication(
          new OAuth2IntrospectionAuthenticatedPrincipal(
              new OpenidClaimSet(authenticatedPrincipal.getAttributes(),
                  addonsProperties.getOps().stream()
                      .filter(openidProvider -> resourceServerProperties.getOpaquetoken()
                          .getIntrospectionUri().contains(openidProvider.getIss().toString()))
                      .findAny().orElse(addonsProperties.getOps().get(0)).getUsernameClaim())
                          .getName(),
              authenticatedPrincipal.getAttributes(),
              (Collection<GrantedAuthority>) authenticatedPrincipal.getAuthorities()),
          new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, introspectedToken,
              toInstant(iatClaim), toInstant(expClaim)),
          authoritiesConverter.convert(authenticatedPrincipal.getAttributes()));
    };
  }

  @Conditional(DefaultCorsFilterCondition.class)
  @Bean
  CorsFilter corsFilter(SpringAddonsOidcProperties addonsProperties) {
    final var corsProps = new ArrayList<>(addonsProperties.getCors());

    return ServletConfigurationSupport.getCorsFilterBean(corsProps);
  }

  private static final Instant toInstant(Object claim) {
    if (claim == null) {
      return null;
    }
    if (claim instanceof Instant i) {
      return i;
    }
    if (claim instanceof Date d) {
      return d.toInstant();
    }
    if (claim instanceof Integer i) {
      return Instant.ofEpochSecond((i).longValue());
    } else if (claim instanceof Long l) {
      return Instant.ofEpochSecond(l);
    } else {
      return null;
    }
  }

}
