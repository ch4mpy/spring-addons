package com.c4_soft.springaddons.rest.reactive;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.matching.AbsentPattern;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.reactive.function.client.WebClient;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import reactor.test.StepVerifier;


@ActiveProfiles("forward-bearer")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableWireMock
class SpringAddonsServerWebClientSupportAnonymousTest {

    @Autowired
    private WebClient test;

    @InjectWireMock
    private WireMockServer wireMockServer;

    @Test
    void forwardingBearerExchangeFilterFunctionTest() {
        // given
        var url = "/forward/bearer";
        // and
        var forwardBearerStub = wireMockServer.stubFor(
                WireMock.get(WireMock.urlEqualTo(url))
                        .willReturn(WireMock.aResponse().withStatus(HttpStatus.OK.value()))
        );

        // when
        var res = test.get()
                .uri(url)
                .retrieve()
                .toBodilessEntity();

        // then
        StepVerifier.create(res)
                .expectNextMatches(voidResponseEntity -> voidResponseEntity.getStatusCode().equals(HttpStatus.OK))
                .verifyComplete();
        // and
        WireMock.verify(WireMock.getRequestedFor(forwardBearerStub.getRequest().getUrlMatcher())
                .withHeader(HttpHeaders.AUTHORIZATION, AbsentPattern.ABSENT));
    }

}
