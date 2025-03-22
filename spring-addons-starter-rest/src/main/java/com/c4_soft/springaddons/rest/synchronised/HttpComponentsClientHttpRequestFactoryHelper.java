package com.c4_soft.springaddons.rest.synchronised;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.routing.DefaultProxyRoutePlanner;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.client5.http.ssl.HttpsSupport;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;

class HttpComponentsClientHttpRequestFactoryHelper {
  public static HttpComponentsClientHttpRequestFactory get(ProxySupport proxySupport,
      ClientHttpRequestFactoryProperties properties)
      throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
    final var httpClientBuilder = HttpClients.custom();

    if (proxySupport != null && proxySupport.isEnabled()) {
      final var proxy = new HttpHost(proxySupport.getHostname().get(), proxySupport.getPort());
      httpClientBuilder.setRoutePlanner(new DefaultProxyRoutePlanner(proxy));
    }

    if (!properties.isSslCertificatesValidationEnabled()) {
      httpClientBuilder.setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
          .setTlsSocketStrategy(new DefaultClientTlsStrategy(
              SSLContextBuilder.create().loadTrustMaterial(TrustAllStrategy.INSTANCE).build(),
              HostnameVerificationPolicy.BOTH, HttpsSupport.getDefaultHostnameVerifier()))
          .build());
    }

    final var clientHttpRequestFactory =
        new HttpComponentsClientHttpRequestFactory(httpClientBuilder.build());
    properties.getReadTimeoutMillis().map(Duration::ofMillis)
        .ifPresent(clientHttpRequestFactory::setReadTimeout);

    return clientHttpRequestFactory;
  }
}
