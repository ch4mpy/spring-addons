package com.c4_soft.springaddons.security.oauth2.test.webmvc;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsWebfluxClientSecurity;

/**
 * To be used when testing secured components which are not controllers
 *
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 * @see    AutoConfigureAddonsWebfluxClientSecurity
 * @see    AutoConfigureAddonsWebmvcResourceServerSecurity
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@EnableAutoConfiguration()
@AutoConfigureAddonsWebmvcMinimalSecurity
public @interface AddonsWebmvcComponentTest {

}
