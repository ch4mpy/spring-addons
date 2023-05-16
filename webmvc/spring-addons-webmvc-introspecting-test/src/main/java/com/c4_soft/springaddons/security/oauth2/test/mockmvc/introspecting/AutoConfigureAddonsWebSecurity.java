package com.c4_soft.springaddons.security.oauth2.test.mockmvc.introspecting;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.boot.autoconfigure.ImportAutoConfiguration;

import com.c4_soft.springaddons.security.oauth2.config.synchronised.AddonsSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.config.synchronised.AddonsWebSecurityBeans;
import com.c4_soft.springaddons.security.oauth2.test.mockmvc.AddonsWebmvcTestConf;

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
@ImportAutoConfiguration({ AddonsWebSecurityBeans.class, AddonsWebmvcTestConf.class })
public @interface AutoConfigureAddonsWebSecurity {
}
