package com.c4_soft.springaddons.rest.syncronished;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClient;

@ActiveProfiles("wiremock")
public class SpringAddonsRestClientBeanDefinitionRegistryPostProcessorTest
        extends AbstractSpringAddonsRestClientBeanDefinitionRegistryPostProcessorTest {

    @Autowired
    private RestClient test;

    @BeforeEach
    public void setup() {
        super.setup(test);
    }
}
