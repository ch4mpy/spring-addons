package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.synchronised.SpringAddonsClientHttpRequestFactory;

/**
 * Verifies that the {@link Executor} passed to {@link SpringAddonsClientHttpRequestFactory} (resolved
 * from the context when use-virtual-threads is enabled) is set on the JDK {@link HttpClient}.
 */
class SpringAddonsClientHttpRequestFactoryVirtualThreadsTest {

  @Test
  void givenAnExecutor_whenCreatingRequest_thenTheJdkHttpClientUsesIt() throws Exception {
    final var http = new ClientHttpRequestFactoryProperties();
    final Executor executor = Runnable::run;

    final var factory =
        new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http, executor);

    assertTrue(jdkHttpClientOf(factory).executor().isPresent());
  }

  @Test
  void givenNoExecutor_whenCreatingRequest_thenTheJdkHttpClientHasNoExplicitExecutor()
      throws Exception {
    final var http = new ClientHttpRequestFactoryProperties();

    final var factory =
        new SpringAddonsClientHttpRequestFactory(new SystemProxyProperties(), http);

    assertTrue(jdkHttpClientOf(factory).executor().isEmpty());
  }

  private static HttpClient jdkHttpClientOf(SpringAddonsClientHttpRequestFactory factory)
      throws Exception {
    final ClientHttpRequest request =
        factory.createRequest(URI.create("https://localhost/test"), HttpMethod.GET);
    final var httpClientField = request.getClass().getDeclaredField("httpClient");
    httpClientField.setAccessible(true);
    return (HttpClient) httpClientField.get(request);
  }
}
