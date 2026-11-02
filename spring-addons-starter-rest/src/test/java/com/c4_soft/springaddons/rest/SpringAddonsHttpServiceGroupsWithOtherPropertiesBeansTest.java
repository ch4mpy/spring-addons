package com.c4_soft.springaddons.rest;

import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.registry.HttpServiceGroup.ClientType;
import org.springframework.web.service.registry.ImportHttpServices;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

/**
 * The HTTP service groups are configured from the environment, whatever the
 * {@link SystemProxyProperties} or {@link SpringAddonsRestProperties} beans of the application
 * (gh-344).
 */
class SpringAddonsHttpServiceGroupsWithOtherPropertiesBeansTest {

  private static WireMockServer server;

  @BeforeAll
  static void startServer() {
    server = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    server.start();
  }

  @AfterAll
  static void stopServer() {
    server.stop();
  }

  @BeforeEach
  void stubPing() {
    server.resetAll();
    server.stubFor(WireMock.get(WireMock.urlEqualTo("/ping")).willReturn(WireMock.ok()));
  }

  @Test
  void givenServletRestClientGroupAndOtherPropertiesBeans_whenGroupProxyIsCalled_thenRequestReachesClientBaseUrl() {
    new WebApplicationContextRunner()
        .withUserConfiguration(RestClientGroupConfiguration.class, OtherPropertiesBeans.class)
        .withPropertyValues(
            "com.c4-soft.springaddons.rest.client.foo-client.base-url=" + server.baseUrl(),
            "com.c4-soft.springaddons.rest.group.foo-group.client=foo-client")
        .run(context -> {
          assertThat(context).hasNotFailed();
          context.getBean(PingApi.class).ping();
        });

    server.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo("/ping")));
  }

  @Test
  void givenServletWebClientGroupAndOtherPropertiesBeans_whenGroupProxyIsCalled_thenRequestReachesClientBaseUrl() {
    new WebApplicationContextRunner()
        .withUserConfiguration(WebClientGroupConfiguration.class, OtherPropertiesBeans.class)
        .withPropertyValues(
            "com.c4-soft.springaddons.rest.client.bar-client.base-url=" + server.baseUrl(),
            "com.c4-soft.springaddons.rest.client.bar-client.type=web-client",
            "com.c4-soft.springaddons.rest.group.bar-group.client=bar-client")
        .run(context -> {
          assertThat(context).hasNotFailed();
          context.getBean(PingApi.class).ping();
        });

    server.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo("/ping")));
  }

  @Test
  void givenReactiveWebClientGroupAndOtherPropertiesBeans_whenGroupProxyIsCalled_thenRequestReachesClientBaseUrl() {
    new ReactiveWebApplicationContextRunner()
        .withUserConfiguration(ReactiveWebClientGroupConfiguration.class,
            OtherPropertiesBeans.class)
        .withPropertyValues(
            "com.c4-soft.springaddons.rest.client.baz-client.base-url=" + server.baseUrl(),
            "com.c4-soft.springaddons.rest.group.baz-group.client=baz-client")
        .run(context -> {
          assertThat(context).hasNotFailed();
          context.getBean(PingApi.class).ping();
        });

    server.verify(1, WireMock.getRequestedFor(WireMock.urlEqualTo("/ping")));
  }

  interface PingApi {
    @GetExchange("/ping")
    void ping();
  }

  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  @ImportHttpServices(group = "foo-group", types = PingApi.class)
  static class RestClientGroupConfiguration {
  }

  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  @ImportHttpServices(group = "bar-group", types = PingApi.class,
      clientType = ClientType.WEB_CLIENT)
  static class WebClientGroupConfiguration {
  }

  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  @ImportHttpServices(group = "baz-group", types = PingApi.class,
      clientType = ClientType.WEB_CLIENT)
  static class ReactiveWebClientGroupConfiguration {
  }

  @Configuration(proxyBeanMethods = false)
  static class OtherPropertiesBeans {
    @Bean
    SystemProxyProperties corpProxy() {
      return new SystemProxyProperties(Optional.of("http://corp-proxy:3128"), List.of());
    }

    @Bean
    SpringAddonsRestProperties otherRestProperties() {
      return new SpringAddonsRestProperties();
    }
  }
}
