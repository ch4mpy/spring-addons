package com.c4_soft.springaddons.security.oauth2.test.webmvc;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import com.c4_soft.springaddons.security.oauth2.test.webflux.AutoConfigureAddonsWebfluxClientSecurity;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.c4_soft.springaddons.security.oidc.starter.synchronised.resourceserver.SpringAddonsOidcResourceServerBeans;

/**
 * <p>
 * Auto-configures {@link SpringAddonsOidcResourceServerBeans} as well as what is already configured
 * by {@link AutoConfigureAddonsWebmvcMinimalSecurity}. To be used to test controllers but not
 * services or repositories (web context is not desired in that case).
 * </p>
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 * @see AddonsWebmvcComponentTest
 * @see AutoConfigureAddonsWebfluxClientSecurity
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@AutoConfigureAddonsWebmvcMinimalSecurity
@ImportAutoConfiguration({SpringAddonsOidcProperties.class,
    SpringAddonsOidcResourceServerBeans.class})
public @interface AutoConfigureAddonsWebmvcResourceServerSecurity {
}
