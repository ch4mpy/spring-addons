package com.c4_soft.springaddons.security.oauth2.test.webmvc.jwt;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.ServletSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ImportAutoConfiguration({ SpringAddonsSecurityProperties.class, ServletSecurityBeans.class, AddonsWebmvcTestConf.class })
public @interface AutoConfigureAddonsSecurityWebmvcJwt {
}
