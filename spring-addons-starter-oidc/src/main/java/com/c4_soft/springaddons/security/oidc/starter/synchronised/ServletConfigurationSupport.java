package com.c4_soft.springaddons.security.oidc.starter.synchronised;

import static org.springframework.security.config.Customizer.withDefaults;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import com.c4_soft.springaddons.security.oidc.starter.properties.CorsProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.Csrf;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.client.ClientExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.client.ClientSynchronizedHttpSecurityPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerExpressionInterceptUrlRegistryPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.ResourceServerSynchronizedHttpSecurityPostProcessor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class ServletConfigurationSupport {

  public static HttpSecurity configureResourceServer(HttpSecurity http,
      ServerProperties serverProperties, SpringAddonsOidcProperties addonsProperties,
      ResourceServerExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
      ResourceServerSynchronizedHttpSecurityPostProcessor httpPostProcessor) throws Exception {

    http.exceptionHandling(exceptions -> {
      final var issuers = addonsProperties.getOps().stream().map(OpenidProviderProperties::getIss)
          .filter(iss -> iss != null).map(URI::toString)
          .collect(Collectors.joining(",", "\"", "\""));
      exceptions.authenticationEntryPoint((request, response, authException) -> {
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "OAuth realm=%s".formatted(issuers));
        response.sendError(HttpStatus.UNAUTHORIZED.value(),
            HttpStatus.UNAUTHORIZED.getReasonPhrase());
      });
    });

    ServletConfigurationSupport.configureState(http,
        addonsProperties.getResourceserver().isStatlessSessions(),
        addonsProperties.getResourceserver().getCsrf());

    // FIXME: use only the new CORS properties at next major release
    final var corsProps = new ArrayList<>(addonsProperties.getCors());
    final var deprecatedClientCorsProps = addonsProperties.getClient().getCors();
    final var deprecatedResourceServerCorsProps = addonsProperties.getResourceserver().getCors();
    corsProps.addAll(deprecatedClientCorsProps);
    corsProps.addAll(deprecatedResourceServerCorsProps);
    ServletConfigurationSupport.configureAccess(http,
        addonsProperties.getResourceserver().getPermitAll(), corsProps, authorizePostProcessor);

    if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
      http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
    }

    return httpPostProcessor.process(http);
  }

  public static HttpSecurity configureClient(HttpSecurity http, ServerProperties serverProperties,
      SpringAddonsOidcProperties addonsProperties,
      ClientExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor,
      ClientSynchronizedHttpSecurityPostProcessor httpPostProcessor) throws Exception {

    ServletConfigurationSupport.configureState(http, false, addonsProperties.getClient().getCsrf());

    // FIXME: use only the new CORS properties at next major release
    final var corsProps = new ArrayList<>(addonsProperties.getCors());
    final var deprecatedClientCorsProps = addonsProperties.getClient().getCors();
    final var deprecatedResourceServerCorsProps = addonsProperties.getResourceserver().getCors();
    corsProps.addAll(deprecatedClientCorsProps);
    corsProps.addAll(deprecatedResourceServerCorsProps);
    ServletConfigurationSupport.configureAccess(http, addonsProperties.getClient().getPermitAll(),
        corsProps, authorizePostProcessor);

    if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
      http.requiresChannel(channel -> channel.anyRequest().requiresSecure());
    }

    return httpPostProcessor.process(http);
  }

  public static HttpSecurity configureAccess(HttpSecurity http, List<String> permitAll,
      List<CorsProperties> corsProperties,
      ExpressionInterceptUrlRegistryPostProcessor authorizePostProcessor) throws Exception {
    final var permittedCorsOptions = corsProperties.stream()
        .filter(cors -> (cors.getAllowedMethods().contains("*")
            || cors.getAllowedMethods().contains("OPTIONS")) && !cors.isDisableAnonymousOptions())
        .map(CorsProperties::getPath).toList();

    if (permitAll.size() > 0 || permittedCorsOptions.size() > 0) {
      http.anonymous(withDefaults());
    }

    if (permitAll.size() > 0) {
      http.authorizeHttpRequests(registry -> registry.requestMatchers(
          permitAll.stream().map(AntPathRequestMatcher::new).toArray(AntPathRequestMatcher[]::new))
          .permitAll());
    }

    if (permittedCorsOptions.size() > 0) {
      http.authorizeHttpRequests(registry -> registry.requestMatchers(permittedCorsOptions.stream()
          .map(corsPathPattern -> new AntPathRequestMatcher(corsPathPattern, "OPTIONS"))
          .toArray(AntPathRequestMatcher[]::new)).permitAll());
    }

    return http
        .authorizeHttpRequests(registry -> authorizePostProcessor.authorizeHttpRequests(registry));
  }

  public static CorsFilter getCorsFilterBean(List<CorsProperties> corsProperties) {
    final var source = new UrlBasedCorsConfigurationSource();
    for (final var corsProps : corsProperties) {
      final var configuration = new CorsConfiguration();
      configuration.setAllowCredentials(corsProps.getAllowCredentials());
      configuration.setAllowedHeaders(corsProps.getAllowedHeaders());
      configuration.setAllowedMethods(corsProps.getAllowedMethods());
      configuration.setAllowedOriginPatterns(corsProps.getAllowedOriginPatterns());
      configuration.setExposedHeaders(corsProps.getExposedHeaders());
      configuration.setMaxAge(corsProps.getMaxAge());
      source.registerCorsConfiguration(corsProps.getPath(), configuration);
    }
    return new CorsFilter(source);
  }

  public static HttpSecurity configureState(HttpSecurity http, boolean isStatless, Csrf csrfEnum)
      throws Exception {

    if (isStatless) {
      http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }

    http.csrf(configurer -> {
      switch (csrfEnum) {
        case DISABLE:
          configurer.disable();
          break;
        case DEFAULT:
          if (isStatless) {
            configurer.disable();
          }
          break;
        case SESSION:
          break;
        case COOKIE_ACCESSIBLE_FROM_JS:
          // https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript
          configurer.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
              .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler());
          break;
      }
    });

    return http;
  }

  static final class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {
    private final CsrfTokenRequestHandler plain = new CsrfTokenRequestAttributeHandler();
    private final CsrfTokenRequestHandler xor = new XorCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
        Supplier<CsrfToken> csrfToken) {
      /*
       * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of the
       * CsrfToken when it is rendered in the response body.
       */
      this.xor.handle(request, response, csrfToken);
      /*
       * Render the token value to a cookie by causing the deferred token to be loaded.
       */
      csrfToken.get();
    }

    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
      String headerValue = request.getHeader(csrfToken.getHeaderName());
      /*
       * If the request contains a request header, use CsrfTokenRequestAttributeHandler to resolve
       * the CsrfToken. This applies when a single-page application includes the header value
       * automatically, which was obtained via a cookie containing the raw CsrfToken.
       *
       * In all other cases (e.g. if the request contains a request parameter), use
       * XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies when a
       * server-side rendered form includes the _csrf request parameter as a hidden input.
       */
      return (StringUtils.hasText(headerValue) ? this.plain : this.xor)
          .resolveCsrfTokenValue(request, csrfToken);
    }
  }
}
