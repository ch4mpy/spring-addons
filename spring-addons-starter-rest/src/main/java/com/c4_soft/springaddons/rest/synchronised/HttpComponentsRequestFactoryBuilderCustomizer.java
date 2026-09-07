package com.c4_soft.springaddons.rest.synchronised;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.function.Consumer;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.client5.http.ssl.HttpsSupport;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.http.client.HttpComponentsClientHttpRequestFactoryBuilder;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;

/**
 * <p>
 * Isolates every reference to {@code org.apache.httpcomponents.client5:httpclient5} types so that
 * this class is loaded (and its bytecode verified) only when a REST client is actually configured
 * with the HTTP_COMPONENTS implementation.
 * </p>
 * <p>
 * {@link SpringAddonsClientHttpRequestFactoryMerger} must never import any httpclient5 type
 * directly: doing so would make class-loading of the merger itself fail with a
 * {@link NoClassDefFoundError} for consumers who don't have httpclient5 on the class-path (it is an
 * optional dependency of spring-addons-starter-rest), even when they never use the HTTP_COMPONENTS
 * implementation.
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
class HttpComponentsRequestFactoryBuilderCustomizer {

  private HttpComponentsRequestFactoryBuilderCustomizer() {}

  @SuppressWarnings("unchecked")
  static HttpComponentsClientHttpRequestFactoryBuilder customize(
      HttpComponentsClientHttpRequestFactoryBuilder builder, @Nullable ProxySupport proxySupport,
      boolean proxyActive, boolean sslValidationDisabled,
      Optional<Consumer<?>> httpClientBuilderConsumer) {
    var b = builder;
    if (sslValidationDisabled) {
      b = b.withConnectionManagerCustomizer(cm -> {
        try {
          cm.setTlsSocketStrategy(new DefaultClientTlsStrategy(
              SSLContextBuilder.create().loadTrustMaterial(TrustAllStrategy.INSTANCE).build(),
              HostnameVerificationPolicy.BOTH, HttpsSupport.getDefaultHostnameVerifier()));
        } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
          throw new RestMisconfigurationException(e);
        }
      });
    }
    if (proxyActive) {
      final var proxy = new HttpHost(proxySupport.getHostname().get(), proxySupport.getPort());
      b = b.withHttpClientCustomizer(
          hcb -> hcb.setRoutePlanner(new DefaultProxyRoutePlanner(proxy)));
    }
    if (httpClientBuilderConsumer.isPresent()) {
      final var consumer =
          (Consumer<HttpClientBuilder>) (Consumer<?>) httpClientBuilderConsumer.get();
      b = b.withHttpClientCustomizer(consumer::accept);
    }
    return b;
  }
}
