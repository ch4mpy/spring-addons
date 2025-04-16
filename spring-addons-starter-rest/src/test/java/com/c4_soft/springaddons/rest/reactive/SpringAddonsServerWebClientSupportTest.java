package com.c4_soft.springaddons.rest.reactive;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.matching.ContainsPattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.test.context.support.ReactorContextTestExecutionListener;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestExecutionListener;
import org.springframework.web.reactive.function.client.WebClient;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import reactor.test.StepVerifier;


@ActiveProfiles("forward-bearer")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableWireMock
class SpringAddonsServerWebClientSupportTest {

    @Autowired
    private WebClient test;

    @InjectWireMock
    private WireMockServer wireMockServer;

    private TestExecutionListener executionListener = new ReactorContextTestExecutionListener();

    private final String token = "TOKEN";

    @BeforeEach
    void setUp() throws Exception {
        var authentication = new JwtAuthenticationToken(Jwt.withTokenValue(token)
                .header("HEADERS", "CANNOT_BE_EMPTY")
                .claim("CLAIMS", "CANNOT_BE_EMPTY")
                .build()
        );
        TestSecurityContextHolder.setAuthentication(authentication);
        executionListener.beforeTestMethod(null);
    }

    @AfterEach
    public void cleanup() throws Exception {
        executionListener.afterTestMethod(null);
    }

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
                .withHeader(HttpHeaders.AUTHORIZATION, new ContainsPattern(token)));
    }

}
