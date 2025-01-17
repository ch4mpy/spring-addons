package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import com.c4_soft.springaddons.security.oauth2.test.AuthenticationFactoriesTestConf;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AddonsWebmvcComponentTest;
import com.c4_soft.springaddons.security.oauth2.test.webmvc.AutoConfigureAddonsWebmvcResourceServerSecurity;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.reactive.ReactiveSpringAddonsOidcBeans;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.SpringAddonsOidcBeans;

/**
 * <p>
 * To be used to test services or repositories but <b>not controllers</b>: auto-configures {@link SpringAddonsOidcProperties}, {@link SpringAddonsOidcBeans},
 * {@link ReactiveSpringAddonsOidcBeans} and {@link AuthenticationFactoriesTestConf}
 * </p>
 * See {@link AddonsWebmvcComponentTest} See {@link AutoConfigureAddonsWebmvcResourceServerSecurity} See {@link AutoConfigureAddonsWebfluxClientSecurity}
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @see    AddonsWebmvcComponentTest
 * @see    AutoConfigureAddonsWebfluxClientSecurity
 * @see    AutoConfigureAddonsWebmvcResourceServerSecurity
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ImportAutoConfiguration(classes = { AddonsWebfluxTestConf.class, ReactiveSpringAddonsOidcBeans.class }, exclude = { SpringAddonsOidcBeans.class })
@ExtendWith(SpringExtension.class)
@TestInstance(Lifecycle.PER_CLASS)
public @interface AutoConfigureAddonsWebfluxMinimalSecurity {
}
