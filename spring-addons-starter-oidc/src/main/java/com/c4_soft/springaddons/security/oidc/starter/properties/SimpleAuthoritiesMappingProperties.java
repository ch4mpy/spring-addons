package com.c4_soft.springaddons.security.oidc.starter.properties;

import com.c4_soft.springaddons.security.oidc.starter.ConfigurableClaimSetAuthoritiesConverter;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration for {@link ConfigurableClaimSetAuthoritiesConverter}
 *
 * @author ch4mp
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
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
		UNCHANGED, UPPER, LOWER
	}
}