package com.c4_soft.springaddons.rest.synchronised;

import static org.assertj.core.api.Assertions.assertThat;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.eclipse.jetty.client.Authentication;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.Request;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties.ClientHttpRequestFactoryProperties.ClientHttpRequestFactoryImpl;
import com.c4_soft.springaddons.rest.SystemProxyProperties;

/**
 * Proxy credentials are registered with the client implementations which need them to answer the
 * 407 challenges of a CONNECT tunnel (setting Proxy-Authorization on the tunneled request is not
 * enough for HttpComponents and Jetty).
 */
class AuthenticatedProxyCredentialsTest {

  @Test
  void givenAuthenticatedProxyAndJettyImpl_whenCreateRequest_thenProxyCredentialsAreInAuthenticationStore()
      throws Exception {
    final var request = factory(ClientHttpRequestFactoryImpl.JETTY)
        .createRequest(URI.create("https://api.example.com/x"), HttpMethod.GET);

    final var requestField = request.getClass().getDeclaredField("request");
    requestField.setAccessible(true);
    final var jettyRequest = (Request) requestField.get(request);
    final var clientField = jettyRequest.getClass().getDeclaredField("client");
    clientField.setAccessible(true);
    final var client = (HttpClient) clientField.get(jettyRequest);

    assertThat(client.getProxyConfiguration().getProxies()).hasSize(1);
    assertThat(client.getAuthenticationStore().findAuthentication("Basic",
        URI.create("http://corp-proxy:3128"), Authentication.ANY_REALM)).isNotNull();
    // the header is still set for plain http:// targets and the JDK implementation
    assertThat(request.getHeaders().getFirst(HttpHeaders.PROXY_AUTHORIZATION))
        .isEqualTo("Basic dXNlcjpzM2NyZXQ=");
  }

  @Test
  void givenAuthenticatedProxyAndHttpComponentsImpl_whenCreateRequest_thenRequestIsCreated()
      throws Exception {
    final ClientHttpRequest request = factory(ClientHttpRequestFactoryImpl.HTTP_COMPONENTS)
        .createRequest(URI.create("https://api.example.com/x"), HttpMethod.GET);

    assertThat(request.getClass().getName()).contains("HttpComponents");
    assertThat(request.getHeaders().getFirst(HttpHeaders.PROXY_AUTHORIZATION))
        .isEqualTo("Basic dXNlcjpzM2NyZXQ=");
  }

  private static SpringAddonsClientHttpRequestFactory factory(ClientHttpRequestFactoryImpl impl) {
    final var properties = new ClientHttpRequestFactoryProperties();
    properties.setClientHttpRequestFactoryImpl(impl);
    return new SpringAddonsClientHttpRequestFactory(
        new SystemProxyProperties(Optional.of("http://user:s3cret@corp-proxy:3128"), List.of()),
        properties);
  }
}
