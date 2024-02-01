package com.c4_soft.springaddons.security.oidc.starter.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;

import lombok.Data;

/**
 * Configuration for {@link ConfigurableClaimSetAuthoritiesConverter}
 *
 * @author ch4mp
 */
@Data
@ConfigurationProperties
public class SimpleAuthoritiesMappingProperties {
    /**
     * JSON path of the claim(s) to map with this properties
     */
    private String path = "$.realm_access.roles";

    /**
     * What to prefix authorities with (for instance "ROLE_" or "SCOPE_")
     */
    private String prefix = "";

    /**
     * Whether to transform authorities to uppercase, lowercase, or to leave it unchanged
     */
    private Case caze = Case.UNCHANGED;

    public static enum Case {
        UNCHANGED,
        UPPER,
        LOWER
    }

}
