package com.c4_soft.springaddons.security.oauth2.test.webflux.jwt;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import com.c4_soft.springaddons.security.oauth2.config.reactive.AddonsSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.config.reactive.AddonsWebSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.config.reactive.SpringAddonsOAuth2ClientBeans;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AddonsWebfluxTestConf;

/**
 * <p>
 * Auto-configures {@link AddonsSecurityBeans} and {@link AddonsWebSecurityBeans}. To be used to test controllers but not services or repositories (web context
 * is not desired in that case).
 * </p>
 * See {@link AutoConfigureAddonsSecurity}
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@AutoConfigureAddonsSecurity
@ImportAutoConfiguration({ AddonsWebSecurityBeans.class, SpringAddonsOAuth2ClientBeans.class, AddonsWebfluxTestConf.class })
public @interface AutoConfigureAddonsWebSecurity {
}
