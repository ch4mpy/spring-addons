package com.c4_soft.springaddons.rest.reactive;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.reactive.function.client.WebClient;

@ActiveProfiles("wiremock-builder")
public class SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessorWithBuilderTest
        extends AbstractSpringAddonsServerWebClientBeanDefinitionRegistryPostProcessorTest {

    @Autowired
    private WebClient.Builder testBuilder;

    @BeforeEach
    public void setup() {
        super.setup(testBuilder.build());
    }
}
