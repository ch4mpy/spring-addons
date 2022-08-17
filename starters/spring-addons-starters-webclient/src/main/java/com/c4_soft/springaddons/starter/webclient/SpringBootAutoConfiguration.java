package com.c4_soft.springaddons.starter.webclient;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({ C4ProxySettings.class, C4WebClientBuilderFactoryService.class })
public class SpringBootAutoConfiguration {
}
