package com.c4soft;

import java.util.Objects;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonValue;

import jakarta.validation.constraints.NotNull;

@RestController
public class DemoController {

	/**
	 * @return a serialized JSON body
	 */
	@GetMapping("/demo")
	public Dto getDemo(
			@RequestParam EnumSerializedByName nameRequestParam,
			@RequestParam EnumSerializedByToString strRequestParam,
			@RequestParam BijectiveEnumSerializedByToString bijRequestParam) {
		return new Dto(nameRequestParam, strRequestParam, bijRequestParam);
	}

	/**
	 * @param  dto response body deserialization using registered {@link HttpMessageConverter message converters} (implementations using
	 *             Jackson)
	 * @return
	 */
	@PutMapping("/demo")
	public ResponseEntity<Void> putDemo(@RequestBody Dto dto) {
		return ResponseEntity.accepted().build();
	}

	public static record Dto(@NotNull EnumSerializedByName name, @NotNull EnumSerializedByToString str, @NotNull BijectiveEnumSerializedByToString bij) {
	}

	/**
	 * <p>
	 * Enum reproducing the bug reported in <a href=https://github.com/springdoc/springdoc-openapi/issues/2494>gh-2494</a>
	 * </p>
	 * <p>
	 * It has a custom toString(), but no &#64;JsonValue nor custom Converter&lt;String, E&gt;
	 * </p>
	 *
	 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	public static enum EnumSerializedByName {
		A("name a"), B("name b");

		String label;

		EnumSerializedByName(String label) {
			this.label = label;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	/**
	 * Enum with {@link HttpMessageConverter message converters} working with toString() because of &#64;JsonValue, but no custom
	 * Converter&lt;String, E&gt;
	 *
	 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	public static enum EnumSerializedByToString {
		A("str a"), B("str b");

		String label;

		EnumSerializedByToString(String label) {
			this.label = label;
		}

		@Override
		@JsonValue // Forces serialization using toString()
		public String toString() {
			return label;
		}
	}

	/**
	 * <p>
	 * What it takes to have an enum serialized and deserialized as per the OpenAPI specs generated by springdoc-openapi
	 * </p>
	 * <p>
	 * Enum with {@link HttpMessageConverter message converters} working with toString() because of &#64;JsonValue, and a custom
	 * Converter&lt;String, E&gt; do deserialize &#64;RequestParam
	 * </p>
	 *
	 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
	 */
	public static enum BijectiveEnumSerializedByToString {
		A("bij a"), B("bij b");

		String label;

		BijectiveEnumSerializedByToString(String label) {
			this.label = label;
		}

		@Override
		@JsonValue // Forces serialization using toString()
		public String toString() {
			return label;
		}

		/**
		 * Inverse operation for the toString() method
		 *
		 * @param  str the serialized value of the enum
		 * @return     deserialized enum value
		 */
		public static BijectiveEnumSerializedByToString fromString(String str) {
			for (final var e : BijectiveEnumSerializedByToString.values()) {
				if (Objects.equals(e.toString(), str)) {
					return e;
				}
			}
			return null;
		}

		/**
		 * Register a Spring converter deserialize &#64;RequestParam from String to {@link BijectiveEnumSerializedByToString}
		 *
		 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
		 */
		@Component
		static class StringEnumSerializedByToStringConverter implements Converter<String, BijectiveEnumSerializedByToString> {
			@Override
			public BijectiveEnumSerializedByToString convert(String source) {
				return BijectiveEnumSerializedByToString.fromString(source);
			}
		}
	}
}
