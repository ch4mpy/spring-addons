package com.c4_soft.springaddons.security.oauth2.test.mockmvc.introspecting;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.c4_soft.springaddons.security.oauth2.config.SpringAddonsSecurityProperties;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.AddonsSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AuthenticationFactoriesTestConf;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ImportAutoConfiguration({ SpringAddonsSecurityProperties.class, AddonsSecurityBeans.class, AuthenticationFactoriesTestConf.class })
@ExtendWith(SpringExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
public @interface AutoConfigureAddonsSecurity {
}
