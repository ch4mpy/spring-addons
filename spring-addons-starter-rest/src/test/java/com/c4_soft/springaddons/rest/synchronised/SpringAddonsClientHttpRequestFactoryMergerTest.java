package com.c4_soft.springaddons.rest.synchronised;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.Optional;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.client.ReactorClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import com.c4_soft.springaddons.rest.ProxySupport;
import com.c4_soft.springaddons.rest.RestMisconfigurationException;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ClientHttpRequestFactoryImpl;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * Unit tests for {@link SpringAddonsClientHttpRequestFactoryMerger}, calling it directly (it is
 * package-private) rather than going through a full Spring context, mirroring the style of
 * {@link SpringAddonsClientHttpRequestFactoryVirtualThreadsTest}.
 */
@ExtendWith(OutputCaptureExtension.class)
class SpringAddonsClientHttpRequestFactoryMergerTest {

  @Test
  void givenNoCustomizationIsNeeded_whenMerging_thenTheContextFactoryIsReusedAsIs() {
    final var contextFactory = new JdkClientHttpRequestFactory(HttpClient.newHttpClient());
    final var props = new ClientHttpRequestFactoryProperties();

    final var result = SpringAddonsClientHttpRequestFactoryMerger.merge("test-client", null, props,
        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.empty(), Optional.of(contextFactory));

    assertSame(contextFactory, result);
  }

  @Test
  void givenContextBuilderIsAnUnsupportedType_andCustomizationIsRequired_whenMerging_thenThrows() {
    final var props = new ClientHttpRequestFactoryProperties();
    props.getProxy().setHost(Optional.of("proxy.example.com"));
    final var proxySupport = new ProxySupport(new SystemProxyProperties(), props.getProxy());
    final ClientHttpRequestFactoryBuilder<?> unsupportedBuilder =
        ClientHttpRequestFactoryBuilder.of(SimpleClientHttpRequestFactory::new);

    assertThrows(RestMisconfigurationException.class,
        () -> SpringAddonsClientHttpRequestFactoryMerger.merge("test-client", proxySupport, props,
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
            Optional.of(unsupportedBuilder), Optional.empty(), Optional.empty()));
  }

  @Test
  void givenSslValidationIsDisabled_andASslBundleIsConfigured_whenMerging_thenTheBundleIsIgnoredWithAWarning(
      CapturedOutput output) {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setSslCertificatesValidationEnabled(false);

    SpringAddonsClientHttpRequestFactoryMerger.merge("warn-client", null, props,
        Optional.of("my-bundle"), Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.empty(), Optional.empty(), Optional.empty());

    assertEquals(true,
        output.getOut().contains("warn-client") && output.getOut().contains("my-bundle"));
  }

  @Test
  void givenTwoClientsShareTheSameContextBuilder_whenMerging_thenEachGetsAnIndependentProxyConfig()
      throws Exception {
    final ClientHttpRequestFactoryBuilder<?> sharedContextBuilder =
        ClientHttpRequestFactoryBuilder.jdk();

    final var props1 = new ClientHttpRequestFactoryProperties();
    props1.getProxy().setHost(Optional.of("proxy-one.example.com"));
    final var proxySupport1 = new ProxySupport(new SystemProxyProperties(), props1.getProxy());
    final var factory1 = SpringAddonsClientHttpRequestFactoryMerger.merge("client-one",
        proxySupport1, props1, Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.empty(), Optional.of(sharedContextBuilder), Optional.empty(), Optional.empty());

    final var props2 = new ClientHttpRequestFactoryProperties();
    props2.getProxy().setHost(Optional.of("proxy-two.example.com"));
    final var proxySupport2 = new ProxySupport(new SystemProxyProperties(), props2.getProxy());
    final var factory2 = SpringAddonsClientHttpRequestFactoryMerger.merge("client-two",
        proxySupport2, props2, Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.empty(), Optional.of(sharedContextBuilder), Optional.empty(), Optional.empty());

    assertEquals("proxy-one.example.com", proxyHostOf(factory1));
    assertEquals("proxy-two.example.com", proxyHostOf(factory2));
  }

  @Test
  void givenSimpleImplIsForced_andProxyIsConfigured_whenMerging_thenTheFactoryUsesTheProxy()
      throws Exception {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.SIMPLE);
    props.getProxy().setHost(Optional.of("proxy.example.com"));
    final var proxySupport = new ProxySupport(new SystemProxyProperties(), props.getProxy());

    final var result = SpringAddonsClientHttpRequestFactoryMerger.merge("simple-client",
        proxySupport, props, Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());

    final var factory = assertInstanceOf(SimpleClientHttpRequestFactory.class, result);
    final var proxyField = SimpleClientHttpRequestFactory.class.getDeclaredField("proxy");
    proxyField.setAccessible(true);
    final var proxy = (java.net.Proxy) proxyField.get(factory);
    assertEquals("proxy.example.com",
        ((InetSocketAddress) proxy.address()).getHostString());
  }

  @Test
  void givenSimpleImplIsForced_andSslValidationIsDisabled_whenMerging_thenThrows() {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.SIMPLE);
    props.setSslCertificatesValidationEnabled(false);

    assertThrows(RestMisconfigurationException.class,
        () -> SpringAddonsClientHttpRequestFactoryMerger.merge("simple-client", null, props,
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
            Optional.empty(), Optional.empty(), Optional.empty()));
  }

  @Test
  void givenSimpleImplIsForced_andHttpProtocolVersionIsSet_whenMerging_thenThrows() {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.SIMPLE);
    props.setHttpProtocolVersion(Optional.of(HttpClient.Version.HTTP_2));

    assertThrows(RestMisconfigurationException.class,
        () -> SpringAddonsClientHttpRequestFactoryMerger.merge("simple-client", null, props,
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
            Optional.empty(), Optional.empty(), Optional.empty()));
  }

  @Test
  void givenSimpleImplIsForced_andVirtualThreadsAreRequested_whenMerging_thenThrows() {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.SIMPLE);
    final Optional<Executor> executor = Optional.of(Runnable::run);

    assertThrows(RestMisconfigurationException.class,
        () -> SpringAddonsClientHttpRequestFactoryMerger.merge("simple-client", null, props,
            Optional.empty(), Optional.empty(), executor, Optional.empty(), Optional.empty(),
            Optional.empty(), Optional.empty()));
  }

  @Test
  void givenReactorImplIsForced_andProxyIsConfigured_whenMerging_thenTheFactoryIsBuilt() {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.REACTOR);
    props.getProxy().setHost(Optional.of("proxy.example.com"));
    final var proxySupport = new ProxySupport(new SystemProxyProperties(), props.getProxy());

    final var result = SpringAddonsClientHttpRequestFactoryMerger.merge("reactor-client",
        proxySupport, props, Optional.empty(), Optional.empty(), Optional.empty(),
        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());

    assertInstanceOf(ReactorClientHttpRequestFactory.class, result);
  }

  @Test
  void givenReactorImplIsForced_andHttpProtocolVersionIsSet_whenMerging_thenThrows() {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.REACTOR);
    props.setHttpProtocolVersion(Optional.of(HttpClient.Version.HTTP_2));

    assertThrows(RestMisconfigurationException.class,
        () -> SpringAddonsClientHttpRequestFactoryMerger.merge("reactor-client", null, props,
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
            Optional.empty(), Optional.empty(), Optional.empty()));
  }

  @Test
  void givenReactorImplIsForced_andVirtualThreadsAreRequested_whenMerging_thenThrows() {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.REACTOR);
    final Optional<Executor> executor = Optional.of(Runnable::run);

    assertThrows(RestMisconfigurationException.class,
        () -> SpringAddonsClientHttpRequestFactoryMerger.merge("reactor-client", null, props,
            Optional.empty(), Optional.empty(), executor, Optional.empty(), Optional.empty(),
            Optional.empty(), Optional.empty()));
  }

  @Test
  void givenReactorImplIsForced_andAConsumerBeanIsConfigured_whenMerging_thenThrows() {
    final var props = new ClientHttpRequestFactoryProperties();
    props.setClientHttpRequestFactoryImpl(ClientHttpRequestFactoryImpl.REACTOR);
    final Optional<java.util.function.Consumer<?>> consumer = Optional.of(x -> {});

    assertThrows(RestMisconfigurationException.class,
        () -> SpringAddonsClientHttpRequestFactoryMerger.merge("reactor-client", null, props,
            Optional.empty(), Optional.empty(), Optional.empty(), consumer, Optional.empty(),
            Optional.empty(), Optional.empty()));
  }

  private static String proxyHostOf(ClientHttpRequestFactory factory) throws Exception {
    final var uri = URI.create("https://localhost/test");
    final var request = factory.createRequest(uri, HttpMethod.GET);
    final var httpClientField = request.getClass().getDeclaredField("httpClient");
    httpClientField.setAccessible(true);
    final var httpClient = (HttpClient) httpClientField.get(request);
    final var proxy = httpClient.proxy().orElseThrow();
    final var address = (InetSocketAddress) proxy.select(uri).get(0).address();
    return address.getHostString();
  }
}
