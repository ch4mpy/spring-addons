package com.c4_soft.springaddons.rest.synchronised;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.registry.ImportHttpServices;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;

/**
 * <p>
 * Checks that an {@code @ImportHttpServices} group backed by "com.c4-soft.springaddons.rest.group"
 * still honors "spring.http.serviceclient.&lt;group-name&gt;.read-timeout" (Spring Boot's own
 * per-group property) when the referenced spring-addons client-id leaves its own read-timeout
 * unset, instead of that setting being silently discarded by the client-id's request factory.
 * </p>
 */
@SpringBootTest(
    classes = SpringAddonsRestClientHttpServiceGroupConfigurerServiceClientPropertiesFallbackTest.GroupTestConfiguration.class,
    properties = {"spring.main.web-application-type=servlet",
        "com.c4-soft.springaddons.rest.client.echo-client.base-url=${wiremock.server.baseUrl}",
        "com.c4-soft.springaddons.rest.group.echo-group.client=echo-client",
        "spring.http.serviceclient.echo-group.read-timeout=50ms"})
@EnableWireMock
class SpringAddonsRestClientHttpServiceGroupConfigurerServiceClientPropertiesFallbackTest {

  @Autowired
  private EchoApi echoApi;

  @InjectWireMock
  private WireMockServer wireMockServer;

  @Test
  void givenGroupServiceClientReadTimeoutIsSetAndClientDoesNotOverrideIt_whenSlowResponseIsReturned_thenReadTimeoutIsHonored() {
    wireMockServer.stubFor(
        WireMock.get(WireMock.urlEqualTo("/ping")).willReturn(WireMock.ok().withFixedDelay(500)));

    assertThrows(ResourceAccessException.class, echoApi::ping);
  }

  interface EchoApi {
    @GetExchange("/ping")
    void ping();
  }

  @Configuration
  @EnableAutoConfiguration
  @ImportHttpServices(group = "echo-group", types = EchoApi.class)
  static class GroupTestConfiguration {
  }
}
