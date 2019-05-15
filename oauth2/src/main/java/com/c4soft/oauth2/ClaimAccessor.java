/*
 * Copyright 2019 Jérôme Wacongne
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.c4soft.oauth2;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.util.Assert;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public interface ClaimAccessor {

	Map<String, Object> getClaims();

	default Object getClaim(String name) {
		Assert.hasLength(name, "claim name can't be empty");
		return getClaims() == null ? null : getClaims().get(name);
	}

	default String getClaimAsString(String name) {
		final Object claim = getClaim(name);
		return claim == null ? null : claim.toString();
	}

	default Instant getClaimAsInstant(String name) {
		final Object claim = getClaim(name);
		if(claim == null) {
			return null;
		}
		if(claim instanceof Long) {
			return Instant.ofEpochSecond((Long) claim);
		}
		if(claim instanceof Instant) {
			return (Instant) claim;
		}
		if(claim instanceof String) {
			return Instant.parse((String) claim);
		}
		throw new RuntimeException("claim " + name + " is of unsupported type " + claim.getClass().getName());
	}

	default Set<String> getClaimAsStringSet(String name) {
		final Object claim = getClaim(name);
		if(claim == null) {
			return null;
		}
		if(claim instanceof Collection<?>) {
			return ((Collection<?>) claim).stream().map(Object::toString).collect(Collectors.toSet());
		}
		if(claim instanceof Object[]) {
			return Stream.of(claim).map(Object::toString).collect(Collectors.toSet());
		}
		return Collections.singleton(claim.toString());
	}

	default URI getClaimAsUri(String name) throws URISyntaxException {
		final Object claim = getClaim(name);
		if(claim == null) {
			return null;
		}
		if(claim instanceof URI) {
			return (URI) claim;
		}
		return new URI(claim.toString());
	}

	default Boolean getClaimAsBoolean(String name) {
		final Object claim = getClaim(name);
		if(claim == null) {
			return null;
		}
		if(claim instanceof Boolean) {
			return (Boolean) claim;
		}
		return Boolean.valueOf(claim.toString());
	}

}
