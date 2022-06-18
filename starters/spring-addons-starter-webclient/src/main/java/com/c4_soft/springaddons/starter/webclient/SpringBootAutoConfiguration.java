package com.c4_soft.springaddons.starter.webclient;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@Import({ C4ProxySettings.class, C4WebClientBuilderFactoryService.class })
public class SpringBootAutoConfiguration {

}
