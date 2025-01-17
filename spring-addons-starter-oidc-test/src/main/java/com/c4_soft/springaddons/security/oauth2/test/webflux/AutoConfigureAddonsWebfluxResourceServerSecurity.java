package com.c4_soft.springaddons.security.oauth2.test.webflux;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import com.c4_soft.springaddons.security.oidc.starter.reactive.resourceserver.ReactiveSpringAddonsOidcResourceServerBeans;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.SpringAddonsOidcResourceServerBeans;

/**
 * <p>
 * Auto-configures {@link ReactiveSpringAddonsOidcResourceServerBeans} and {@link AddonsWebfluxTestConf}. To be used to test controllers but not services or
 * repositories (web context is not desired in that case).
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@AutoConfigureAddonsWebfluxMinimalSecurity
@ImportAutoConfiguration(classes = { ReactiveSpringAddonsOidcResourceServerBeans.class }, exclude = { SpringAddonsOidcResourceServerBeans.class })
public @interface AutoConfigureAddonsWebfluxResourceServerSecurity {
}
