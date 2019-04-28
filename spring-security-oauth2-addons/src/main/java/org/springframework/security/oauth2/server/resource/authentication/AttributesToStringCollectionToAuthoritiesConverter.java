package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;

/**
 * <p>Two steps conversion from token attributes to authorities.</p>
 * <p>Sample use-cases: extract scopes and then turn it into authorities.</p>
 *
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class AttributesToStringCollectionToAuthoritiesConverter implements Converter<Map<String, Object>, Collection<GrantedAuthority>> {
	private final Converter<Map<String, Object>, List<String>> stringCollectionConverter;
	private final Converter<Collection<String>, Collection<GrantedAuthority>> authoritiesConverter;

	@Autowired
	public AttributesToStringCollectionToAuthoritiesConverter(
			Converter<Map<String, Object>, List<String>> stringCollectionConverter,
			Converter<Collection<String>, Collection<GrantedAuthority>> authoritiesConverter) {
		this.stringCollectionConverter = stringCollectionConverter;
		this.authoritiesConverter = authoritiesConverter;
	}

	@Override
	public Collection<GrantedAuthority> convert(Map<String, Object> source) {
		return authoritiesConverter.convert(stringCollectionConverter.convert(source));
	}

}