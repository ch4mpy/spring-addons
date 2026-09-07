package com.c4_soft.springaddons.rest.synchronised;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.registry.ImportHttpServices;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.BasicCredentials;
import com.github.tomakehurst.wiremock.client.WireMock;

/**
 * End-to-end check that an {@code @ImportHttpServices} group referencing an auto-configured
 * client (via "com.c4-soft.springaddons.rest.group") is configured (base URL, authorization
 * included) exactly like that client-id's own {@link RestClient} bean.
 */
@SpringBootTest(
    classes = SpringAddonsRestClientHttpServiceGroupConfigurerTest.GroupTestConfiguration.class,
    properties = {"spring.main.web-application-type=servlet",
        "com.c4-soft.springaddons.rest.client.echo-client.base-url=${wiremock.server.baseUrl}",
        "com.c4-soft.springaddons.rest.client.echo-client.authorization.basic.username=spring-backend",
        "com.c4-soft.springaddons.rest.client.echo-client.authorization.basic.password=secret",
        "com.c4-soft.springaddons.rest.group.echo-group.client=echo-client"})
@EnableWireMock
class SpringAddonsRestClientHttpServiceGroupConfigurerTest {

  @Autowired
  private RestClient echoClient;

  @Autowired
  private EchoApi echoApi;

  @InjectWireMock
  private WireMockServer wireMockServer;

  @Test
  void givenClientHasBasicAuthConfigured_whenGroupProxyIsCalled_thenTheSameAuthorizationHeaderIsSent() {
    wireMockServer.stubFor(WireMock.get(WireMock.urlEqualTo("/ping")).willReturn(WireMock.ok()));

    echoApi.ping();

    wireMockServer.verify(WireMock.getRequestedFor(WireMock.urlEqualTo("/ping"))
        .withBasicAuth(new BasicCredentials("spring-backend", "secret")));
  }

  @Test
  void givenClientHasBasicAuthConfigured_whenRawClientIsCalled_thenTheSameAuthorizationHeaderIsSent() {
    wireMockServer.stubFor(WireMock.get(WireMock.urlEqualTo("/ping")).willReturn(WireMock.ok()));

    echoClient.get().uri("/ping").retrieve().toBodilessEntity();

    wireMockServer.verify(WireMock.getRequestedFor(WireMock.urlEqualTo("/ping"))
        .withBasicAuth(new BasicCredentials("spring-backend", "secret")));
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
