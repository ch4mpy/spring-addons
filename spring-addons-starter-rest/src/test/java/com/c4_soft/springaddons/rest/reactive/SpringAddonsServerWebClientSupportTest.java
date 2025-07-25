package com.c4_soft.springaddons.rest.reactive;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.web.reactive.function.client.WebClient;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithJwt;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.matching.AbsentPattern;
import com.github.tomakehurst.wiremock.matching.ContainsPattern;
import reactor.test.StepVerifier;


@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"spring.main.web-application-type=reactive"})
@EnableWireMock
class SpringAddonsServerWebClientSupportTest {

  @Autowired
  private WebClient fooClient;

  @InjectWireMock
  private WireMockServer wireMockServer;

  private final String token = "machin.truc.bidule";

  @Test
  void givenAnEmptySecurityContext_whenSendRequestWithForwardingBearerExchangeFilterFunction_thenAuthorizationHeaderIsNotSet() {
    // given
    var url = "/forward/bearer";
    // and
    var forwardBearerStub = wireMockServer.stubFor(WireMock.get(WireMock.urlEqualTo(url))
        .willReturn(WireMock.aResponse().withStatus(HttpStatus.OK.value())));

    // when
    var res = fooClient.get().uri(url).retrieve().toBodilessEntity();

    // then
    StepVerifier.create(res)
        .expectNextMatches(
            voidResponseEntity -> voidResponseEntity.getStatusCode().equals(HttpStatus.OK))
        .verifyComplete();
    // and
    WireMock.verify(WireMock.getRequestedFor(forwardBearerStub.getRequest().getUrlMatcher())
        .withHeader(HttpHeaders.AUTHORIZATION, AbsentPattern.ABSENT));
  }

  @Test
  @WithAnonymousUser
  void givenUserIsAnonymous_whenSendRequestWithForwardingBearerExchangeFilterFunction_thenAuthorizationHeaderIsNotSet() {
    // given
    var url = "/forward/bearer";
    // and
    var forwardBearerStub = wireMockServer.stubFor(WireMock.get(WireMock.urlEqualTo(url))
        .willReturn(WireMock.aResponse().withStatus(HttpStatus.OK.value())));

    // when
    var res = fooClient.get().uri(url).retrieve().toBodilessEntity();

    // then
    StepVerifier.create(res)
        .expectNextMatches(
            voidResponseEntity -> voidResponseEntity.getStatusCode().equals(HttpStatus.OK))
        .verifyComplete();
    // and
    WireMock.verify(WireMock.getRequestedFor(forwardBearerStub.getRequest().getUrlMatcher())
        .withHeader(HttpHeaders.AUTHORIZATION, AbsentPattern.ABSENT));
  }

  @Test
  @WithJwt(file = "ch4mp.json", bearerString = token)
  void givenUserIsAuthenticated_whenSendRequestWithForwardingBearerExchangeFilterFunction_thenAuthorizationHeaderIsSet() {
    // given
    var url = "/forward/bearer";
    // and
    var forwardBearerStub = wireMockServer.stubFor(WireMock.get(WireMock.urlEqualTo(url))
        .willReturn(WireMock.aResponse().withStatus(HttpStatus.OK.value())));

    // when
    var res = fooClient.get().uri(url).retrieve().toBodilessEntity();

    // then
    StepVerifier.create(res)
        .expectNextMatches(
            voidResponseEntity -> voidResponseEntity.getStatusCode().equals(HttpStatus.OK))
        .verifyComplete();
    // and
    WireMock.verify(WireMock.getRequestedFor(forwardBearerStub.getRequest().getUrlMatcher())
        .withHeader(HttpHeaders.AUTHORIZATION, new ContainsPattern(token)));
  }

}
