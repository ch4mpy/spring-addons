package com.c4_soft.springaddons.security.oidc.starter;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import com.c4_soft.springaddons.security.oidc.starter.properties.SimpleAuthoritiesMappingProperties;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;

import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Portable converter to extract Spring-security authorities from OAuth2 claims.
 * </p>
 * <p>
 * It is designed to work with {@link SpringAddonsOidcProperties} which enable to configure:
 * </p>
 * <ul>
 * <li>source claims (which claims to pick authorities from, dot.separated.path is supported)</li>
 * <li>for each claim: prefix (should anything like "ROLE_" or "PREFIX_" be pre-pended to authorities)</li>
 * <li>for each claim: case transformation (should be authorities be forced to uppercase, lowercase or be left untouched)</li>
 * </ul>
 *
 * @author ch4mp
 */
@RequiredArgsConstructor
public class ConfigurableClaimSetAuthoritiesConverter implements ClaimSetAuthoritiesConverter {
    private final AuthoritiesMappingPropertiesResolver authoritiesMappingPropertiesProvider;

    public ConfigurableClaimSetAuthoritiesConverter(SpringAddonsOidcProperties properties) {
        this.authoritiesMappingPropertiesProvider = new ByIssuerAuthoritiesMappingPropertiesResolver(properties);
    }

    @Override
    public Collection<? extends GrantedAuthority> convert(Map<String, Object> source) {
        final var authoritiesMappingProperties = authoritiesMappingPropertiesProvider.resolve(source);
        // @formatter:off
	    return authoritiesMappingProperties.stream()
	            .flatMap(authoritiesMappingProps -> getAuthorities(source, authoritiesMappingProps))
	            .map(r -> (GrantedAuthority) new SimpleGrantedAuthority(r)).toList();
	    // @formatter:on
    }

    private static String processCase(String role, SimpleAuthoritiesMappingProperties.Case caze) {
        switch (caze) {
            case UPPER: {
                return role.toUpperCase();
            }
            case LOWER: {
                return role.toLowerCase();
            }
            default:
                return role;
        }
    }

    private static Stream<String> getAuthorities(Map<String, Object> claims, SimpleAuthoritiesMappingProperties props) {
        // @formatter:off
	    return getClaims(claims, props.getPath())
	    		.flatMap(claim -> Stream.of(claim.split(",")))
	    		.flatMap(claim -> Stream.of(claim.split(" ")))
	    		.filter(StringUtils::hasText)
	    		.map(String::trim)
	            .map(r -> processCase(r, props.getCaze()))
	            .map(r -> String.format("%s%s", props.getPrefix(), r));
	    // @formatter:on
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static Stream<String> getClaims(Map<String, Object> claims, String path) {
        try {
            final var res = JsonPath.read(claims, path);
            if (res instanceof String r) {
                return Stream.of(r);
            }
            if (res instanceof List l) {
                if (l.size() == 0) {
                    return Stream.empty();
                }
                if (l.get(0) instanceof String) {
                    return l.stream();
                }
                if (l.get(0) instanceof List) {
                    return l.stream().flatMap(o -> ((List) o).stream());
                }
            }
            return Stream.empty();
        } catch (PathNotFoundException e) {
            return Stream.empty();
        }
    }
}
