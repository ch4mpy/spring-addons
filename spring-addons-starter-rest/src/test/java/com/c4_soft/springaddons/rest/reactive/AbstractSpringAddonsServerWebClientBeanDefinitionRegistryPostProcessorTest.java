package com.c4_soft.springaddons.rest.reactive;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = AbstractSpringAddonsServerWebClientBeanDefinitionRegistryPostProcessorTest.AlwaysTeaPotTestConfiguration.class
)
@EnableWireMock
public abstract class AbstractSpringAddonsServerWebClientBeanDefinitionRegistryPostProcessorTest {

    private WebClient client;

    @InjectWireMock
    private WireMockServer wireMockServer;

    protected void setup(WebClient client) {
        this.client = client;
    }

    @Test
    protected void givenAClientWithAPreconfiguredInterceptorAsGlobalBean_whenSendAnyRequest_thenTheInterceptorIsUsed() {
        // given
        var url = "/api/endpoint";

        // when
        var res = client.get()
                .uri(url)
                .retrieve()
                .toBodilessEntity();

        // then
        StepVerifier.create(res)
                .expectErrorMatches(t -> t instanceof WebClientResponseException e && e.getStatusCode().equals(HttpStatus.I_AM_A_TEAPOT))
                .verify();
        // and
        wireMockServer.verify(
                WireMock.exactly(0),
                WireMock.anyRequestedFor(WireMock.anyUrl())
        );
    }

    @TestConfiguration
    protected static class AlwaysTeaPotTestConfiguration {

        @Bean
        public WebClient.Builder webClientBuilder() {
            return WebClient.builder()
                    .filter((request, next) -> Mono.just(ClientResponse.create(HttpStatus.I_AM_A_TEAPOT).build()));
        }

    }
}
