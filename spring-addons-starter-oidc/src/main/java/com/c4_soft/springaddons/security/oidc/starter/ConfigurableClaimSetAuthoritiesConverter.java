package com.c4_soft.springaddons.security.oidc.starter;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Stream;
import org.springframework.lang.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;
import com.c4_soft.springaddons.security.oidc.starter.properties.NotAConfiguredOpenidProviderException;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcProperties.OpenidProviderProperties.SimpleAuthoritiesMappingProperties;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.PathNotFoundException;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * Portable converter to extract Spring-security authorities from OAuth2 claims.
 * </p>
 * <p>
 * It relies on {@link OpenidProviderPropertiesResolver} to resolve the configuration properties for
 * the provided claims (and throws if it is not resolved). This properties enable to configure:
 * </p>
 * <ul>
 * <li>source claims (which claims to pick authorities from, dot.separated.path is supported)</li>
 * <li>for each claim: prefix (should anything like "ROLE_" or "PREFIX_" be pre-pended to
 * authorities)</li>
 * <li>for each claim: case transformation (should be authorities be forced to uppercase, lowercase
 * or be left untouched)</li>
 * </ul>
 *
 * @author ch4mp
 */
@RequiredArgsConstructor
public class ConfigurableClaimSetAuthoritiesConverter implements ClaimSetAuthoritiesConverter {
  private final OpenidProviderPropertiesResolver opPropertiesResolver;

  @Override
  public Collection<? extends GrantedAuthority> convert(@NonNull Map<String, Object> source) {
    final var opProperties = opPropertiesResolver.resolve(source)
        .orElseThrow(() -> new NotAConfiguredOpenidProviderException(source));
    // @formatter:off
	    return opProperties.getAuthorities().stream()
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

  private static Stream<String> getAuthorities(Map<String, Object> claims,
      SimpleAuthoritiesMappingProperties props) {
    // @formatter:off
	    return getClaims(claims, props.getPath())
	    		.filter(StringUtils::hasText)
	    		.map(String::trim)
	            .map(r -> processCase(r, props.getCaze()))
	            .map(r -> String.format("%s%s", props.getPrefix(), r));
	    // @formatter:on
  }

  /**
   * @return the string values found at the given path: a single string is split on commas and
   *         spaces, string items of a list (or of a list of lists, as returned by JSON path
   *         expressions matching several nodes) are taken as they are, other items are ignored
   */
  private static Stream<String> getClaims(Map<String, Object> claims, String path) {
    try {
      final Object res = JsonPath.read(claims, path);
      if (res instanceof String r) {
        return Stream.of(r).flatMap(claim -> Stream.of(claim.split(",")))
            .flatMap(claim -> Stream.of(claim.split(" ")));
      }
      if (res instanceof Collection<?> items) {
        return items.stream().flatMap(ConfigurableClaimSetAuthoritiesConverter::stringItems);
      }
      return Stream.empty();
    } catch (PathNotFoundException e) {
      return Stream.empty();
    }
  }

  private static Stream<String> stringItems(Object item) {
    if (item instanceof String s) {
      return Stream.of(s);
    }
    if (item instanceof Collection<?> nested) {
      return nested.stream().filter(String.class::isInstance).map(String.class::cast);
    }
    return Stream.empty();
  }
}
