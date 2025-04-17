package com.c4_soft.springaddons.rest.reactive;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.reactive.function.client.WebClient;

@ActiveProfiles("wiremock")
public class SpringAddonsServerWebClientBeanDefinitionRegistryPostProcessorTest
        extends AbstractSpringAddonsServerWebClientBeanDefinitionRegistryPostProcessorTest {

    @Autowired
    private WebClient test;

    @BeforeEach
    public void setup() {
        super.setup(test);
    }
}
