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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

/**
 * @author Jérôme Wacongne &lt;ch4mp#64;c4-soft.com&gt;
 *
 */
public class UnmodifiableTokenPropertiesTest {

	@Test(expected = UnsupportedOperationException.class)
	public void putThrowsException() {
		final var props = new UnmodifiableTokenProperties(Map.of("name1", "value1"));
		props.put("name1", "overriden");
	}

	@Test(expected = UnsupportedOperationException.class)
	public void putOrRemoveStringThrowsException() {
		final var props = new UnmodifiableTokenProperties(Map.of("name1", "value1"));
		props.putOrRemove("name1", "overriden");
	}

	@Test(expected = UnsupportedOperationException.class)
	public void putOrRemoveCollectionThrowsException() {
		final var props = new UnmodifiableTokenProperties(Map.of("name1", "value1"));
		props.putOrRemove("name1", Set.of("overriden"));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void putOrRemoveObjectThrowsException() {
		final var props = new UnmodifiableTokenProperties(Map.of("name1", "value1"));
		props.putOrRemove("name1", 1L);
	}

	@Test
	public void getAsBooleanReturnsBooleanValue() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"boolean", Boolean.TRUE));
		assertThat(props.getAsBoolean("boolean")).isEqualTo(true);
	}

	@Test
	public void getAsBooleanReturnsBooleanValueFromString() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"boolean", "true"));
		assertThat(props.getAsBoolean("boolean")).isEqualTo(true);
	}

	@Test
	public void getAsBooleanReturnsFalseFromEmptyString() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"boolean", ""));
		assertThat(props.getAsBoolean("boolean")).isEqualTo(false);
	}

	@Test
	public void getAsStringActuallyReturnsString() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"boolean", Boolean.TRUE,
				"string", "value",
				"stringSet", Set.of("value1", "value2"),
				"long", 42L,
				"instant", Instant.parse("2019-05-20T20:58:00Z"), "uri", "https://github.com/ch4mpy"));
		assertThat(props.getAsString("boolean")).isEqualTo("true");
		assertThat(props.getAsString("string")).isEqualTo("value");
		assertThat(props.getAsString("stringSet")).contains("value1");
		assertThat(props.getAsString("stringSet")).contains("value2");
		assertThat(props.getAsString("long")).isEqualTo("42");
		assertThat(props.getAsString("instant")).isEqualTo("2019-05-20T20:58:00Z");
	}

	@Test
	public void getAsStringSetFromSpaceSeparatedStringReturnsSplittedValue() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"stringSet", "value1 value2"));
		assertThat(props.getAsStringSet("stringSet")).containsExactlyInAnyOrder("value1", "value2");
	}

	@Test
	public void getAsStringSetFromObjectCollectionReturnsSplittedValue() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"stringSet", Set.of(Boolean.TRUE, 42L, "value1 value2"))) ;
		assertThat(props.getAsStringSet("stringSet")).containsExactlyInAnyOrder("true", "42", "value1", "value2");
	}

	@Test
	public void getAsInstantFromInstantReturnsInstant() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"instant", Instant.parse("2019-05-20T20:58:00Z"))) ;
		assertThat(props.getAsInstant("instant")).isEqualTo(Instant.parse("2019-05-20T20:58:00Z"));
	}

	@Test
	public void getAsInstantFromStringReturnsInstant() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"instant", "2019-05-20T20:58:00Z")) ;
		assertThat(props.getAsInstant("instant")).isEqualTo(Instant.parse("2019-05-20T20:58:00Z"));
	}

	@Test
	public void getAsInstantFromLongReturnsInstant() {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"instant", Instant.parse("2019-05-20T20:58:00Z").getEpochSecond())) ;
		assertThat(props.getAsInstant("instant")).isEqualTo(Instant.parse("2019-05-20T20:58:00Z"));
	}

	@Test
	public void getAsUriFromStringReturnsUri() throws URISyntaxException {
		final var props = new UnmodifiableTokenProperties(Map.of(
				"uri", "https://github.com/ch4mpy")) ;
		assertThat(props.getAsUri("uri")).isEqualTo(new URI("https://github.com/ch4mpy"));
	}

}
