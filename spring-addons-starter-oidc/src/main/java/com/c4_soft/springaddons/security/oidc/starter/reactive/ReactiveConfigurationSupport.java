package com.c4_soft.springaddons.security.oidc.starter.reactive;

import static org.springframework.security.config.Customizer.withDefaults;
import java.net.URI;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import com.c4_soft.springaddons.security.oidc.starter.properties.CorsProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.Csrf;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties;
import com.c4_soft.springaddons.security.oidc.starter.reactive.client.ClientAuthorizeExchangeSpecPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.reactive.client.ClientReactiveHttpSecurityPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ResourceServerAuthorizeExchangeSpecPostProcessor;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ResourceServerReactiveHttpSecurityPostProcessor;
import reactor.core.publisher.Mono;

public class ReactiveConfigurationSupport {

  public static ServerHttpSecurity configureResourceServer(ServerHttpSecurity http,
      ServerProperties serverProperties, SpringAddonsOidcProperties addonsProperties,
      ResourceServerAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
      ResourceServerReactiveHttpSecurityPostProcessor httpPostProcessor,
      Optional<CookieServerCsrfTokenRepositoryPostProcessor> csrfPostProcessor) {

    http.exceptionHandling(exceptions -> {
      final var issuers = addonsProperties.getOps().stream().map(OpenidProviderProperties::getIss)
          .filter(iss -> iss != null).map(URI::toString)
          .collect(Collectors.joining(",", "\"", "\""));
      exceptions
          .authenticationEntryPoint((ServerWebExchange exchange, AuthenticationException ex) -> {
            var response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE,
                "OAuth realm=%s".formatted(issuers));
            var dataBufferFactory = response.bufferFactory();
            var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
            return response.writeWith(Mono.just(buffer))
                .doOnError(error -> DataBufferUtils.release(buffer));
          });
    });

    ReactiveConfigurationSupport.configureState(http,
        addonsProperties.getResourceserver().isStatlessSessions(),
        addonsProperties.getResourceserver().getCsrf(), addonsProperties.getResourceserver().getCsrfCookieName(),
        addonsProperties.getResourceserver().getCsrfCookiePath(),
        csrfPostProcessor);

    // FIXME: use only the new CORS properties at next major release
    final var corsProps = new ArrayList<>(addonsProperties.getCors());
    final var deprecatedClientCorsProps = addonsProperties.getClient().getCors();
    final var deprecatedResourceServerCorsProps = addonsProperties.getResourceserver().getCors();
    corsProps.addAll(deprecatedClientCorsProps);
    corsProps.addAll(deprecatedResourceServerCorsProps);
    ReactiveConfigurationSupport.configureAccess(http,
        addonsProperties.getResourceserver().getPermitAll(), corsProps);

    if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
      http.redirectToHttps(withDefaults());
    }

    http.authorizeExchange(registry -> authorizePostProcessor.authorizeHttpRequests(registry));
    httpPostProcessor.process(http);

    return http;
  }

  public static ServerHttpSecurity configureClient(ServerHttpSecurity http,
      ServerProperties serverProperties, SpringAddonsOidcProperties addonsProperties,
      ClientAuthorizeExchangeSpecPostProcessor authorizePostProcessor,
      ClientReactiveHttpSecurityPostProcessor httpPostProcessor,
      Optional<CookieServerCsrfTokenRepositoryPostProcessor> csrfPostProcessor) {

    ReactiveConfigurationSupport.configureState(http, false,
        addonsProperties.getClient().getCsrf(),  addonsProperties.getClient().getCsrfCookieName(),
        addonsProperties.getClient().getCsrfCookiePath(),
        csrfPostProcessor);

    // FIXME: use only the new CORS properties at next major release
    final var corsProps = new ArrayList<>(addonsProperties.getCors());
    final var deprecatedClientCorsProps = addonsProperties.getClient().getCors();
    final var deprecatedResourceServerCorsProps = addonsProperties.getResourceserver().getCors();
    corsProps.addAll(deprecatedClientCorsProps);
    corsProps.addAll(deprecatedResourceServerCorsProps);
    ReactiveConfigurationSupport.configureAccess(http, addonsProperties.getClient().getPermitAll(),
        corsProps);

    if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
      http.redirectToHttps(withDefaults());
    }

    http.authorizeExchange(registry -> authorizePostProcessor.authorizeHttpRequests(registry));
    httpPostProcessor.process(http);

    return http;
  }

  public static ServerHttpSecurity configureAccess(ServerHttpSecurity http, List<String> permitAll,
      List<CorsProperties> corsProperties) {
    final var permittedCorsOptions = corsProperties.stream()
        .filter(cors -> (cors.getAllowedMethods().contains("*")
            || cors.getAllowedMethods().contains("OPTIONS")) && !cors.isDisableAnonymousOptions())
        .map(CorsProperties::getPath).toList();

    if (permitAll.size() > 0 || permittedCorsOptions.size() > 0) {
      http.anonymous(withDefaults());
    }

    if (permitAll.size() > 0) {
      http.authorizeExchange(authorizeExchange -> authorizeExchange
          .pathMatchers(permitAll.toArray(new String[] {})).permitAll());
    }

    if (permittedCorsOptions.size() > 0) {
      http.authorizeExchange(authorizeExchange -> authorizeExchange
          .pathMatchers(HttpMethod.OPTIONS, permittedCorsOptions.toArray(new String[] {}))
          .permitAll());
    }

    return http;
  }

  public static CorsWebFilter getCorsFilterBean(List<CorsProperties> corsProperties) {
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
    return new CorsWebFilter(source);
  }

  public static ServerHttpSecurity configureState(ServerHttpSecurity http, boolean isStatless,
      Csrf csrfEnum, String csrfCookieName, String csrfCookiePath,
      Optional<CookieServerCsrfTokenRepositoryPostProcessor> csrfPostProcessor) {

    if (isStatless) {
      http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance());
    }

    http.csrf(csrf -> {
      switch (csrfEnum) {
        case DISABLE:
          csrf.disable();
          break;
        case DEFAULT:
          if (isStatless) {
            csrf.disable();
          } else {
            withDefaults();
          }
          break;
        case SESSION:
          withDefaults();
          break;
        case COOKIE_ACCESSIBLE_FROM_JS:
          // adapted from
          // https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa
          final var repo = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
          repo.setCookiePath(csrfCookiePath);
          repo.setCookieName(csrfCookieName);
          csrf.csrfTokenRepository(csrfPostProcessor.map(pp -> pp.process(repo)).orElse(repo))
              .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler());
          break;
      }
    });

    return http;
  }

  /**
   * Adapted from
   * https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#csrf-integration-javascript-spa
   */
  static final class SpaCsrfTokenRequestHandler extends ServerCsrfTokenRequestAttributeHandler {
    private final ServerCsrfTokenRequestAttributeHandler delegate =
        new XorServerCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken) {
      /*
       * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of the
       * CsrfToken when it is rendered in the response body.
       */
      this.delegate.handle(exchange, csrfToken);
    }

    @Override
    public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
      /*
       * If the request contains a X-XSRF-TOKEN header, use it. This applies when a single-page
       * application includes the header value automatically, which was obtained via a cookie
       * containing the raw CsrfToken. In all other cases (e.g. if the request contains a request
       * parameter), use XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies
       * when a server-side rendered form includes the _csrf request parameter as a hidden input.
       */
      return Mono
          .justOrEmpty(exchange.getRequest().getHeaders().getFirst(csrfToken.getHeaderName()))
          .switchIfEmpty(this.delegate.resolveCsrfTokenValue(exchange, csrfToken));
    }
  }
}
