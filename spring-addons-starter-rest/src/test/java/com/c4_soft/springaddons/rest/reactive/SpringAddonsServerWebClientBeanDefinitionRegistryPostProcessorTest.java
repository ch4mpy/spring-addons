package com.c4_soft.springaddons.rest.reactive;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessorTest.AlwaysTeaPotTestConfiguration.class)
@EnableWireMock
public class SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessorTest {

  @Autowired
  private WebClient fooClient;

  @Autowired
  private WebClient.Builder barClientBuilder;

  @InjectWireMock
  private WireMockServer wireMockServer;

  @Test
  protected void givenAClientWithAPreconfiguredInterceptorAsGlobalBean_whenSendAnyRequestWithFoo_thenTheInterceptorIsUsed() {
    // given
    var url = "/api/endpoint";

    // when
    var res = fooClient.get().uri(url).retrieve().toBodilessEntity();

    // then
    StepVerifier.create(res).expectErrorMatches(t -> t instanceof WebClientResponseException e
        && e.getStatusCode().equals(HttpStatus.I_AM_A_TEAPOT)).verify();
    // and
    wireMockServer.verify(WireMock.exactly(0), WireMock.anyRequestedFor(WireMock.anyUrl()));
  }

  @Test
  protected void givenAClientWithAPreconfiguredInterceptorAsGlobalBean_whenSendAnyRequestWithBar_thenTheInterceptorIsUsed() {
    // given
    var url = "/api/endpoint";

    // when
    var res = barClientBuilder.build().get().uri(url).retrieve().toBodilessEntity();

    // then
    StepVerifier.create(res).expectErrorMatches(t -> t instanceof WebClientResponseException e
        && e.getStatusCode().equals(HttpStatus.I_AM_A_TEAPOT)).verify();
    // and
    wireMockServer.verify(WireMock.exactly(0), WireMock.anyRequestedFor(WireMock.anyUrl()));
  }

  @TestConfiguration
  static class AlwaysTeaPotTestConfiguration {

    @Bean
    WebClient.Builder webClientBuilder() {
      return WebClient.builder().filter(
          (request, next) -> Mono.just(ClientResponse.create(HttpStatus.I_AM_A_TEAPOT).build()));
    }

  }
}
