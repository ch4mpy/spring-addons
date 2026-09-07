package com.c4_soft.springaddons.rest.synchronised;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.http.client.HttpComponentsClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.JdkClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.JettyClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.ReactorClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.SimpleClientHttpRequestFactoryBuilder;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ClientHttpRequestFactoryImpl;
import lombok.extern.slf4j.Slf4j;

/**
 * <p>
 * Merges spring-addons REST client HTTP customization (proxy, timeouts, SSL certificates
 * validation, protocol version, virtual threads, consumer bean) with the
 * {@link ClientHttpRequestFactoryBuilder} / {@link ClientHttpRequestFactory} beans resolved from
 * the context by Spring Boot auto-configuration.
 * </p>
 * <p>
 * The context builder is never mutated: when a client requires customization, a dedicated instance
 * is built for that client only. When nothing needs to be added, the context
 * {@link ClientHttpRequestFactory} bean is reused as-is.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Slf4j
class SpringAddonsClientHttpRequestFactoryMerger {

  private SpringAddonsClientHttpRequestFactoryMerger() {}

  static ClientHttpRequestFactory merge(String clientId, @Nullable ProxySupport proxySupport,
      ClientHttpRequestFactoryProperties addonsHttp, Optional<String> sslBundleName,
      Optional<SslBundle> resolvedSslBundle, Optional<Executor> virtualThreadsExecutor,
      Optional<Consumer<?>> httpClientBuilderConsumer,
      Optional<ClientHttpRequestFactoryBuilder<?>> contextBuilder,
      Optional<HttpClientSettings> contextSettings,
      Optional<ClientHttpRequestFactory> legacyContextFactory) {

    final var proxyActive = proxySupport != null && proxySupport.isEnabled();
    final var sslValidationDisabled = !addonsHttp.isSslCertificatesValidationEnabled();
    final var impl = addonsHttp.getClientHttpRequestFactoryImpl();
    final var implForced = impl != ClientHttpRequestFactoryImpl.FROM_CONTEXT;

    final var needsCustomization = proxyActive || sslValidationDisabled
        || addonsHttp.getHttpProtocolVersion().isPresent() || virtualThreadsExecutor.isPresent()
        || httpClientBuilderConsumer.isPresent() || implForced
        || addonsHttp.getConnectTimeoutMillis().isPresent()
        || addonsHttp.getReadTimeoutMillis().isPresent() || sslBundleName.isPresent();

    if (!needsCustomization) {
      if (legacyContextFactory.isPresent()) {
        final var factory = legacyContextFactory.get();
        log.info("REST client '{}' HTTP request factory: reused unmodified from context ({})",
            clientId, factory.getClass().getSimpleName());
        return factory;
      }
      var builder = contextBuilder.orElseGet(ClientHttpRequestFactoryBuilder::jdk);
      // Since Spring Boot 4.1, JdkClientHttpRequestFactoryBuilder defaults to
      // ProxySelector.getDefault(), which can silently pick up a JVM-wide system proxy. When this
      // factory must not use any spring-addons-configured proxy (proxySupport is null), force it
      // off explicitly instead of inheriting that default. withHttpClientCustomizer (unlike the
      // Boot-4.1-only withProxySelector) is available since Boot 4.0, and its customizer runs
      // after Boot's own default-proxy assignment, so this also stays a harmless no-op on 4.0.x
      // (where no default proxy is ever set in the first place).
      if (proxySupport == null && builder instanceof JdkClientHttpRequestFactoryBuilder jdk) {
        builder = jdk.withHttpClientCustomizer(hcb -> hcb.proxy(ProxySelector.of(null)));
      }
      final var settings = contextSettings.orElseGet(HttpClientSettings::defaults);
      final var factory = builder.build(settings);
      log.info(
          "REST client '{}' HTTP request factory: built with defaults ({}), no ClientHttpRequestFactory bean found in context (is spring-boot-http-client on the class-path?)",
          clientId, factory.getClass().getSimpleName());
      return factory;
    }

    final ClientHttpRequestFactoryBuilder<?> selectedBuilder;
    final String path;
    if (implForced) {
      selectedBuilder = switch (impl) {
        case JDK -> ClientHttpRequestFactoryBuilder.jdk();
        case HTTP_COMPONENTS -> ClientHttpRequestFactoryBuilder.httpComponents();
        case JETTY -> ClientHttpRequestFactoryBuilder.jetty();
        case REACTOR -> ClientHttpRequestFactoryBuilder.reactor();
        case SIMPLE -> ClientHttpRequestFactoryBuilder.simple();
        default -> throw new IllegalStateException("unreachable: impl is forced");
      };
      path = "built a forced instance";
    } else if (contextBuilder.isPresent()) {
      selectedBuilder = contextBuilder.get();
      path = "context builder enriched";
    } else {
      // No spring-boot-http-client on the class-path (or the class was instantiated directly,
      // typically from a test, without a context builder): fall back to the same default as
      // before FROM_CONTEXT existed.
      selectedBuilder = ClientHttpRequestFactoryBuilder.jdk();
      path = "built with defaults (no ClientHttpRequestFactoryBuilder bean found in context)";
    }

    var settings = contextSettings.orElseGet(HttpClientSettings::defaults);
    if (addonsHttp.getConnectTimeoutMillis().isPresent()) {
      settings =
          settings.withConnectTimeout(Duration.ofMillis(addonsHttp.getConnectTimeoutMillis().get()));
    }
    if (addonsHttp.getReadTimeoutMillis().isPresent()) {
      settings =
          settings.withReadTimeout(Duration.ofMillis(addonsHttp.getReadTimeoutMillis().get()));
    }
    if (sslValidationDisabled) {
      if (sslBundleName.isPresent()) {
        log.warn(
            "REST client '{}': ssl-bundle '{}' is ignored because ssl-certificates-validation-enabled is false",
            clientId, sslBundleName.get());
      }
    } else if (resolvedSslBundle.isPresent()) {
      settings = settings.withSslBundle(resolvedSslBundle.get());
    }

    final var customizedBuilder = customize(clientId, selectedBuilder, addonsHttp, proxySupport,
        proxyActive, sslValidationDisabled, virtualThreadsExecutor, httpClientBuilderConsumer);

    final var factory = customizedBuilder.build(settings);
    log.info("REST client '{}' HTTP request factory: {} ({})", clientId, path,
        factory.getClass().getSimpleName());

    return factory;
  }

  @SuppressWarnings("unchecked")
  private static ClientHttpRequestFactoryBuilder<?> customize(String clientId,
      ClientHttpRequestFactoryBuilder<?> builder, ClientHttpRequestFactoryProperties addonsHttp,
      @Nullable ProxySupport proxySupport, boolean proxyActive, boolean sslValidationDisabled,
      Optional<Executor> virtualThreadsExecutor, Optional<Consumer<?>> httpClientBuilderConsumer) {

    if (builder instanceof HttpComponentsClientHttpRequestFactoryBuilder httpComponents) {
      return HttpComponentsRequestFactoryBuilderCustomizer.customize(httpComponents, proxySupport,
          proxyActive, sslValidationDisabled, httpClientBuilderConsumer);
    }

    if (builder instanceof JdkClientHttpRequestFactoryBuilder jdk) {
      var b = jdk.withHttpClientCustomizer(hcb -> {
        if (proxyActive) {
          final var proxyAddress =
              new InetSocketAddress(proxySupport.getHostname().get(), proxySupport.getPort());
          hcb.proxy(ProxySelector.of(proxyAddress));
        } else {
          // Since Spring Boot 4.1, the builder defaults to ProxySelector.getDefault(), which can
          // silently pick up a JVM-wide system proxy. Force no proxy explicitly rather than
          // leaving that default in place.
          hcb.proxy(ProxySelector.of(null));
        }
        addonsHttp.getHttpProtocolVersion().ifPresent(hcb::version);
        if (sslValidationDisabled) {
          hcb.sslContext(trustAllSslContext());
        }
        httpClientBuilderConsumer
            .ifPresent(c -> ((Consumer<HttpClient.Builder>) (Consumer<?>) c).accept(hcb));
      });
      if (virtualThreadsExecutor.isPresent()) {
        b = b.withExecutor(virtualThreadsExecutor.get());
      }
      return b;
    }

    if (builder instanceof JettyClientHttpRequestFactoryBuilder jetty) {
      return JettyRequestFactoryBuilderCustomizer.customize(jetty, proxySupport, proxyActive,
          sslValidationDisabled, virtualThreadsExecutor, addonsHttp.getHttpProtocolVersion(),
          httpClientBuilderConsumer);
    }

    if (builder instanceof ReactorClientHttpRequestFactoryBuilder reactor) {
      if (addonsHttp.getHttpProtocolVersion().isPresent()) {
        throw new RestMisconfigurationException(
            "REST client '%s' has an http-protocol-version configured, but the Reactor implementation does not support it (force JDK or JETTY instead)"
                .formatted(clientId));
      }
      if (virtualThreadsExecutor.isPresent()) {
        throw new RestMisconfigurationException(
            "REST client '%s' has use-virtual-threads set to true, but the Reactor implementation runs on its own event-loop threads and does not support a custom executor (force JDK or JETTY instead)"
                .formatted(clientId));
      }
      if (httpClientBuilderConsumer.isPresent()) {
        throw new RestMisconfigurationException(
            "REST client '%s' has an http-client-builder-consumer-bean configured, but the underlying reactor.netty.http.client.HttpClient is immutable (fluent) and cannot be customized through a Consumer (force JDK, HTTP_COMPONENTS or JETTY instead)"
                .formatted(clientId));
      }
      return ReactorRequestFactoryBuilderCustomizer.customize(reactor, proxySupport, proxyActive,
          sslValidationDisabled);
    }

    if (builder instanceof SimpleClientHttpRequestFactoryBuilder simple) {
      if (sslValidationDisabled) {
        throw new RestMisconfigurationException(
            "REST client '%s' has ssl-certificates-validation-enabled set to false, but the Simple (java.net.HttpURLConnection based) implementation does not support disabling SSL certificate validation (force JDK, HTTP_COMPONENTS, JETTY or REACTOR instead)"
                .formatted(clientId));
      }
      if (addonsHttp.getHttpProtocolVersion().isPresent()) {
        throw new RestMisconfigurationException(
            "REST client '%s' has an http-protocol-version configured, but the Simple (java.net.HttpURLConnection based) implementation only supports HTTP/1.1 (force JDK, HTTP_COMPONENTS, JETTY or REACTOR instead)"
                .formatted(clientId));
      }
      if (virtualThreadsExecutor.isPresent()) {
        throw new RestMisconfigurationException(
            "REST client '%s' has use-virtual-threads set to true, but the Simple (java.net.HttpURLConnection based) implementation does not support running requests on a custom executor (force JDK, HTTP_COMPONENTS, JETTY or REACTOR instead)"
                .formatted(clientId));
      }
      var b = simple;
      if (proxyActive) {
        final var proxyAddress =
            new InetSocketAddress(proxySupport.getHostname().get(), proxySupport.getPort());
        b = b.withCustomizer(factory -> factory.setProxy(new Proxy(Proxy.Type.HTTP, proxyAddress)));
      }
      if (httpClientBuilderConsumer.isPresent()) {
        final var consumer =
            (Consumer<SimpleClientHttpRequestFactory>) (Consumer<?>) httpClientBuilderConsumer.get();
        b = b.withCustomizer(consumer::accept);
      }
      return b;
    }

    throw new RestMisconfigurationException(
        "REST client '%s' requires HTTP customization (proxy, SSL, protocol version, virtual threads or a consumer bean) but the ClientHttpRequestFactoryBuilder bean resolved from the context is a %s, which spring-addons-starter-rest cannot enrich (only HttpComponents, JDK, Jetty, Reactor and Simple builders are supported)"
            .formatted(clientId, builder.getClass().getName()));
  }

  private static SSLContext trustAllSslContext() {
    try {
      final var sslContext = SSLContext.getInstance("TLS");
      final var trustManager = new X509TrustManager() {
        @Override
        public X509Certificate[] getAcceptedIssuers() {
          return new X509Certificate[] {};
        }

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {}

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1)
            throws CertificateException {}
      };
      sslContext.init(null, new TrustManager[] {trustManager}, new SecureRandom());
      return sslContext;
    } catch (NoSuchAlgorithmException | KeyManagementException e) {
      throw new RestMisconfigurationException(e);
    }
  }
}
