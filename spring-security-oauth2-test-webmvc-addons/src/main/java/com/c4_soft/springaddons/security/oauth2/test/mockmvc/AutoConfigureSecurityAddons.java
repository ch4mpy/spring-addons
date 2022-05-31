package com.c4_soft.springaddons.security.oauth2.test.mockmvc;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import com.c4_soft.springaddons.security.oauth2.config.synchronised.ServletSecurityBeans;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ImportAutoConfiguration(classes = { AddonsWebmvcTestConf.class, ServletSecurityBeans.class })
public @interface AutoConfigureSecurityAddons {

}
