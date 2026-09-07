package com.c4_soft.springaddons.rest.synchronised;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * <p>
 * An implementation of {@link ClientHttpRequestFactory} that sends the request through an HTTP or
 * SOCKS proxy when it is enabled and when the request URI does not match the NO_PROXY pattern.
 * </p>
 * <p>
 * When going through a proxy, the Proxy-Authorization header is set if username and password are
 * non-empty.
 * </p>
 * <p>
 * The underlying (proxy and no-proxy) {@link ClientHttpRequestFactory} delegates are resolved by
 * {@link SpringAddonsClientHttpRequestFactoryMerger}, which reuses or enriches the
 * {@code ClientHttpRequestFactoryBuilder} / {@code ClientHttpRequestFactory} beans resolved from
 * the context, when provided.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class SpringAddonsClientHttpRequestFactory implements ClientHttpRequestFactory {
  private final Optional<Pattern> nonProxyHostsPattern;
  private final ClientHttpRequestFactory proxyDelegate;
  private final ClientHttpRequestFactory noProxyDelegate;

  public SpringAddonsClientHttpRequestFactory(SystemProxyProperties systemProperties,
      ClientHttpRequestFactoryProperties addonsProperties) {
    this(systemProperties, addonsProperties, Optional.empty(), Optional.empty());
  }

  public SpringAddonsClientHttpRequestFactory(SystemProxyProperties systemProperties,
      ClientHttpRequestFactoryProperties addonsProperties, Optional<Executor> executor) {
    this(systemProperties, addonsProperties, executor, Optional.empty());
  }

  /**
   * @param executor the {@link Executor} to set on the underlying client when use-virtual-threads is
   *        enabled (typically the application task executor resolved from the context). Honored by
   *        the JDK and Jetty implementations.
   * @param httpClientBuilderConsumer optional {@link Consumer} bean applied to the
   *        implementation-specific client builder just before the request factory is built. The
   *        consumed type depends on the configured implementation:
   *        {@code java.net.http.HttpClient.Builder} (JDK),
   *        {@code org.apache.hc.client5.http.impl.classic.HttpClientBuilder} (HTTP_COMPONENTS) or
   *        {@code org.eclipse.jetty.client.HttpClient} (JETTY).
   */
  public SpringAddonsClientHttpRequestFactory(SystemProxyProperties systemProperties,
      ClientHttpRequestFactoryProperties addonsProperties, Optional<Executor> executor,
      Optional<? extends Consumer<?>> httpClientBuilderConsumer) {
    this("", systemProperties, addonsProperties, executor, httpClientBuilderConsumer,
        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
  }

  /**
   * @param clientId the spring-addons REST client id, used for logging and error messages.
   * @param executor the {@link Executor} to set on the underlying client when use-virtual-threads is
   *        enabled (typically the application task executor resolved from the context). Honored by
   *        the JDK and Jetty implementations.
   * @param httpClientBuilderConsumer optional {@link Consumer} bean applied to the
   *        implementation-specific client builder just before the request factory is built. The
   *        consumed type depends on the configured implementation:
   *        {@code java.net.http.HttpClient.Builder} (JDK),
   *        {@code org.apache.hc.client5.http.impl.classic.HttpClientBuilder} (HTTP_COMPONENTS) or
   *        {@code org.eclipse.jetty.client.HttpClient} (JETTY).
   * @param sslBundleName name of the ssl-bundle configured for this client, if any.
   * @param resolvedSslBundle the {@link SslBundle} resolved from sslBundleName, if any.
   * @param contextBuilder the {@code ClientHttpRequestFactoryBuilder} bean resolved from the
   *        context, if any (populated by Spring Boot auto-configuration since Spring Boot 4).
   * @param contextSettings the {@code HttpClientSettings} bean resolved from the context, if any.
   * @param legacyContextFactory the {@link ClientHttpRequestFactory} bean resolved from the
   *        context, if any.
   */
  public SpringAddonsClientHttpRequestFactory(String clientId,
      SystemProxyProperties systemProperties, ClientHttpRequestFactoryProperties addonsProperties,
      Optional<Executor> executor, Optional<? extends Consumer<?>> httpClientBuilderConsumer,
      Optional<String> sslBundleName, Optional<SslBundle> resolvedSslBundle,
      Optional<ClientHttpRequestFactoryBuilder<?>> contextBuilder,
      Optional<HttpClientSettings> contextSettings,
      Optional<ClientHttpRequestFactory> legacyContextFactory) {
    final var proxySupport = new ProxySupport(systemProperties, addonsProperties.getProxy());

    this.nonProxyHostsPattern = proxySupport.isEnabled()
        ? Optional.ofNullable(proxySupport.getNoProxy()).map(Pattern::compile)
        : Optional.empty();

    this.noProxyDelegate = clientHttpRequestFactory(clientId, null, addonsProperties, executor,
        httpClientBuilderConsumer, sslBundleName, resolvedSslBundle, contextBuilder,
        contextSettings, legacyContextFactory);

    if (proxySupport.isEnabled()) {
      this.proxyDelegate = new ProxyAwareClientHttpRequestFactory(clientId, proxySupport,
          addonsProperties, executor, httpClientBuilderConsumer, sslBundleName, resolvedSslBundle,
          contextBuilder, contextSettings, legacyContextFactory);
    } else {
      this.proxyDelegate = this.noProxyDelegate;
    }
  }

  @Override
  public @NonNull ClientHttpRequest createRequest(@NonNull URI uri, @NonNull HttpMethod httpMethod)
      throws IOException {
    final var delegate = nonProxyHostsPattern.filter(pattern -> {
      final var matcher = pattern.matcher(uri.getHost());
      return matcher.matches();
    }).map(isNoProxy -> {
      return noProxyDelegate;
    }).orElse(proxyDelegate);

    return delegate.createRequest(uri, httpMethod);
  }

  private static ClientHttpRequestFactory clientHttpRequestFactory(String clientId,
      @Nullable ProxySupport proxySupport, ClientHttpRequestFactoryProperties properties,
      Optional<Executor> executor, Optional<? extends Consumer<?>> httpClientBuilderConsumer,
      Optional<String> sslBundleName, Optional<SslBundle> resolvedSslBundle,
      Optional<ClientHttpRequestFactoryBuilder<?>> contextBuilder,
      Optional<HttpClientSettings> contextSettings,
      Optional<ClientHttpRequestFactory> legacyContextFactory) {
    return SpringAddonsClientHttpRequestFactoryMerger.merge(clientId, proxySupport, properties,
        sslBundleName, resolvedSslBundle, executor, httpClientBuilderConsumer.map(c -> (Consumer<?>) c),
        contextBuilder, contextSettings, legacyContextFactory);
  }

  public static class ProxyAwareClientHttpRequestFactory implements ClientHttpRequestFactory {
    private final ClientHttpRequestFactory delegate;
    private final @Nullable String username;
    private final @Nullable String password;

    public ProxyAwareClientHttpRequestFactory(ProxySupport proxySupport,
        ClientHttpRequestFactoryProperties properties, Optional<Executor> executor,
        Optional<? extends Consumer<?>> httpClientBuilderConsumer) {
      this("", proxySupport, properties, executor, httpClientBuilderConsumer, Optional.empty(),
          Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
    }

    public ProxyAwareClientHttpRequestFactory(String clientId, ProxySupport proxySupport,
        ClientHttpRequestFactoryProperties properties, Optional<Executor> executor,
        Optional<? extends Consumer<?>> httpClientBuilderConsumer, Optional<String> sslBundleName,
        Optional<SslBundle> resolvedSslBundle,
        Optional<ClientHttpRequestFactoryBuilder<?>> contextBuilder,
        Optional<HttpClientSettings> contextSettings,
        Optional<ClientHttpRequestFactory> legacyContextFactory) {
      this.username = proxySupport.getUsername();
      this.password = proxySupport.getPassword();
      this.delegate = clientHttpRequestFactory(clientId, proxySupport, properties, executor,
          httpClientBuilderConsumer, sslBundleName, resolvedSslBundle, contextBuilder,
          contextSettings, legacyContextFactory);
    }

    @Override
    public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
      final var request = delegate.createRequest(uri, httpMethod);
      if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
        final var base64 = Base64.getEncoder()
            .encodeToString((username + ':' + password).getBytes(StandardCharsets.UTF_8));
        request.getHeaders().set(HttpHeaders.PROXY_AUTHORIZATION, "Basic %s".formatted(base64));
      }
      return request;
    }
  }

}
