package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import com.c4_soft.springaddons.security.oauth2.config.reactive.ReactiveSecurityBeans;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ImportAutoConfiguration(classes = { AddonsWebfluxTestConf.class, ReactiveSecurityBeans.class })
public @interface AutoConfigureSecurityAddons {

}
