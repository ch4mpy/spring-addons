package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import java.net.http.HttpClient;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ClientHttpRequestFactoryImpl;
import com.c4_soft.springaddons.rest.synchronised.SpringAddonsClientHttpRequestFactory;

/**
 * Verifies the {@code http.http-protocol-version} mapping for the Jetty implementation: HTTP/1.1
 * goes through the over-HTTP transport and HTTP/2 through the over-HTTP/2 transport (the
 * jetty-http2-client dependencies are on the test class-path).
 */
class SpringAddonsClientHttpRequestFactoryJettyVersionTest {

  @Test
  void givenJettyAndHttp1_1_whenBuildingFactory_thenSucceeds() {
    final var http = new ClientHttpRequestFactoryProperties();
    http.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.JETTY);
    http.setHttpProtocolVersion(Optional.of(HttpClient.Version.HTTP_1_1));

    assertDoesNotThrow(
        () -> new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http));
  }

  @Test
  void givenJettyAndHttp2_whenBuildingFactory_thenSucceeds() {
    final var http = new ClientHttpRequestFactoryProperties();
    http.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.JETTY);
    http.setHttpProtocolVersion(Optional.of(HttpClient.Version.HTTP_2));

    assertDoesNotThrow(
        () -> new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http));
  }
}
