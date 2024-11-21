package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcComponentTest;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcMinimalSecurity;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oidc.starter.reactive.client.ReactiveSpringAddonsOidcClientWithLoginBeans;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ReactiveSpringAddonsOidcResourceServerBeans;

/**
 * <p>
 * Auto-configures {@link ReactiveSpringAddonsOidcResourceServerBeans} and {@link AddonsWebfluxTestConf}. To be used to test controllers but not services or
 * repositories (web context is not desired in that case).
 * </p>
 * See {@link AutoConfigureAddonsWebmvcMinimalSecurity}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @see    AddonsWebmvcComponentTest
 * @see    AutoConfigureAddonsWebmvcResourceServerSecurity
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@AutoConfigureAddonsWebfluxMinimalSecurity
@ImportAutoConfiguration({ ReactiveSpringAddonsOidcClientWithLoginBeans.class, AddonsWebfluxTestConf.class })
public @interface AutoConfigureAddonsWebfluxClientSecurity {
}
