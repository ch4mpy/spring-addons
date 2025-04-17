package com.c4_soft.springaddons.rest.synchronised;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.wiremock.spring.EnableWireMock;
import org.wiremock.spring.InjectWireMock;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = AbstractSpringAddonsRestClientBeanDefinitionRegistryPostProcessorTest.AlwaysTeaPotTestConfiguration.class,
        properties = {"spring.main.web-application-type=servlet"}
)
@EnableWireMock
public abstract class AbstractSpringAddonsRestClientBeanDefinitionRegistryPostProcessorTest {

    private RestClient client;

    @InjectWireMock
    private WireMockServer wireMockServer;

    protected void setup(RestClient client) {
        this.client = client;
    }

    @Test
    protected void givenAClientWithAPreconfiguredInterceptorAsGlobalBean_whenSendAnyRequest_thenTheInterceptorIsUsed() {
        // given
        var url = "/api/endpoint";

        // when
        Exception exception = null;
        try {
            client.get()
                    .uri(url)
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception e) {
            exception = e;
        }

        // then
        Assertions.assertNotNull(exception);
        HttpClientErrorException clientError = (HttpClientErrorException) exception;
        Assertions.assertEquals(HttpStatus.I_AM_A_TEAPOT, clientError.getStatusCode());
        // and
        wireMockServer.verify(
                WireMock.exactly(0),
                WireMock.anyRequestedFor(WireMock.anyUrl())
        );
    }

    @TestConfiguration
    protected static class AlwaysTeaPotTestConfiguration {

        @Bean
        public RestClient.Builder restClientBuilder() {
            return RestClient.builder()
                    .requestInterceptor((request, body, execution) -> new MockClientHttpResponse(new byte[0], HttpStatus.I_AM_A_TEAPOT));
        }

    }
}
