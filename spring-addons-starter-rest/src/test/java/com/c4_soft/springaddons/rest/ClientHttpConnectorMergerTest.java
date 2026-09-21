package com.c4_soft.springaddons.rest;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;

/**
 * On Spring Boot 3.4 (no reactive {@code ClientHttpConnectorBuilder}), the context
 * {@link ClientHttpConnector} bean is reused as-is when nothing needs to be customized, and a
 * dedicated Reactor Netty connector is built otherwise.
 */
class ClientHttpConnectorMergerTest {

  private final ClientHttpConnector contextConnector = new ReactorClientHttpConnector();

  @Test
  void givenNoCustomization_whenMerge_thenContextConnectorIsReused() {
    final var connector = ClientHttpConnectorMerger.merge("machin", new SystemProxyProperties(),
        new ClientHttpRequestFactoryProperties(), Optional.empty(), Optional.empty(),
        Optional.of(contextConnector));

    assertThat(connector).isSameAs(contextConnector);
  }

  @Test
  void givenNoCustomizationAndNoContextConnector_whenMerge_thenReactorConnectorIsBuilt() {
    final var connector = ClientHttpConnectorMerger.merge("machin", new SystemProxyProperties(),
        new ClientHttpRequestFactoryProperties(), Optional.empty(), Optional.empty(),
        Optional.empty());

    assertThat(connector).isInstanceOf(ReactorClientHttpConnector.class);
  }

  @Test
  void givenTimeouts_whenMerge_thenDedicatedConnectorIsBuilt() {
    final var http = new ClientHttpRequestFactoryProperties();
    http.setConnectTimeoutMillis(Optional.of(1500));

    final var connector = ClientHttpConnectorMerger.merge("machin", new SystemProxyProperties(),
        http, Optional.empty(), Optional.empty(), Optional.of(contextConnector));

    assertThat(connector).isInstanceOf(ReactorClientHttpConnector.class)
        .isNotSameAs(contextConnector);
  }

  @Test
  void givenSslValidationDisabled_whenMerge_thenDedicatedConnectorIsBuilt() {
    final var http = new ClientHttpRequestFactoryProperties();
    http.setSslCertificatesValidationEnabled(false);

    final var connector = ClientHttpConnectorMerger.merge("machin", new SystemProxyProperties(),
        http, Optional.empty(), Optional.empty(), Optional.of(contextConnector));

    assertThat(connector).isInstanceOf(ReactorClientHttpConnector.class)
        .isNotSameAs(contextConnector);
  }
}
