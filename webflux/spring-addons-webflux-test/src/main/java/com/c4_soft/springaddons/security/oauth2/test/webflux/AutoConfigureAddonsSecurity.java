package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({ AddonsWebfluxTestConf.class, SpringAddonsSecurityProperties.class })
public @interface AutoConfigureAddonsSecurity {

}
