package com.c4_soft.springaddons.rest.synchronised;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * http_proxy / https_proxy selection by target scheme, with the (default) JDK implementation.
 */
class SpringAddonsClientHttpRequestFactorySchemeProxyTest {

  @Test
  void givenHttpAndHttpsProxies_whenCreateRequest_thenProxySelectedByTargetScheme()
      throws Exception {
    final var system = new SystemProxyProperties(Optional.of("http://http-proxy:3128"),
        Optional.of("http://https-proxy:3129"), List.of("localhost"));
    final var factory =
        new SpringAddonsClientHttpRequestFactory(system, new ClientHttpRequestFactoryProperties());

    assertThat(proxyOf(factory, "http://api.example.com/x")).contains("http-proxy:3128");
    assertThat(proxyOf(factory, "https://api.example.com/x")).contains("https-proxy:3129");
    assertThat(proxyOf(factory, "https://localhost/x")).isEmpty();
  }

  @Test
  void givenOnlyHttpsProxy_whenCreateRequest_thenUsedForHttpTargetsToo() throws Exception {
    final var system = new SystemProxyProperties(Optional.empty(),
        Optional.of("http://https-proxy:3129"), List.of());
    final var factory =
        new SpringAddonsClientHttpRequestFactory(system, new ClientHttpRequestFactoryProperties());

    assertThat(proxyOf(factory, "http://api.example.com/x")).contains("https-proxy:3129");
    assertThat(proxyOf(factory, "https://api.example.com/x")).contains("https-proxy:3129");
  }

  @Test
  void givenProxyHostInProperties_whenCreateRequest_thenPropertiesWinForBothSchemes()
      throws Exception {
    final var system = new SystemProxyProperties(Optional.of("http://http-proxy:3128"),
        Optional.of("http://https-proxy:3129"), List.of());
    final var properties = new ClientHttpRequestFactoryProperties();
    properties.getProxy().setHost(Optional.of("corp-proxy"));
    properties.getProxy().setPort(8080);
    final var factory = new SpringAddonsClientHttpRequestFactory(system, properties);

    assertThat(proxyOf(factory, "http://api.example.com/x")).contains("corp-proxy:8080");
    assertThat(proxyOf(factory, "https://api.example.com/x")).contains("corp-proxy:8080");
  }

  private static Optional<String> proxyOf(SpringAddonsClientHttpRequestFactory factory,
      String uri) throws Exception {
    final ClientHttpRequest request = factory.createRequest(URI.create(uri), HttpMethod.GET);
    final var field = request.getClass().getDeclaredField("httpClient");
    field.setAccessible(true);
    final var httpClient = (HttpClient) field.get(request);
    return httpClient.proxy().map(selector -> selector.select(URI.create(uri)))
        .flatMap(proxies -> proxies.stream().filter(p -> p.type() != Proxy.Type.DIRECT).findFirst())
        .map(Proxy::address).map(InetSocketAddress.class::cast)
        .map(address -> address.getHostString() + ":" + address.getPort());
  }
}
