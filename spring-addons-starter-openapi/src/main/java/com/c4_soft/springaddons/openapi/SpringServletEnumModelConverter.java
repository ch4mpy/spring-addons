package com.c4_soft.springaddons.openapi;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springdoc.core.providers.ObjectMapperProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import io.swagger.v3.core.converter.AnnotatedType;
import io.swagger.v3.core.converter.ModelConverter;
import io.swagger.v3.core.converter.ModelConverterContext;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import lombok.RequiredArgsConstructor;

/**
 * <p>
 * A Swagger {@link ModelConverter} to produce decent possible enum values in the OpenAPI spec of Spring applications.
 * </p>
 * The values are generated differently depending on the enum being:
 * <ul>
 * <li>part of a {@link RequestBody &#64;RequestBody} or {@link ResponseBody &#64;ResponseBody}: use {@link HttpMessageConverter}</li>
 * <li>a {@link RequestParam &#64;RequestParam}: scan for a custom {@link Converter Converter&lt;String, E&gt;}. If none is found, use the
 * enum name() (which is what the default converter does). If a custom converter is registered as a bean, then try to give it as input in
 * the following order: the Jackson converter output, the value of toString() and enum name()</li>
 * </ul>
 * 
 * @author ch4mp&#64;c4-soft.com
 */
@RequiredArgsConstructor
public class SpringServletEnumModelConverter implements ModelConverter {

	private final ApplicationContext applicationContext;
	private final ObjectMapperProvider springDocObjectMapper;

	@SuppressWarnings("unchecked")
	@Override
	public Schema<?> resolve(AnnotatedType type, ModelConverterContext context, Iterator<ModelConverter> chain) {

		final var mapper = springDocObjectMapper.jsonMapper();
		final var javaType = mapper.constructType(type.getType());

		if (javaType == null || !javaType.isEnumType()) {
			return chain.hasNext() ? chain.next().resolve(type, context, chain) : null;
		}

		final var enumClass = (Class<Enum<?>>) javaType.getRawClass();
		final var httpMessagePossibleValues = getHttpMessagePossibleValuesFor(enumClass);
		final var namePossibleValues = EnumPossibleValuesExtractor.byName().getValues(enumClass);

		if (context.getDefinedModels().size() > 0 && httpMessagePossibleValues.size() > 0) {
			// Case of an enum part of a @RequestBody or @ResponseBody: use HttpMessageConverter
			return schemaOf(httpMessagePossibleValues);
		}

		// Case of an enum as @RequestParam
		Class<Enum<?>> typeClass;
		try {
			typeClass = (Class<Enum<?>>) Class.forName(type.getType().getTypeName());
		} catch (ClassNotFoundException e) {
			throw new RuntimeException(e);
		}
		final var converters = Stream.of(applicationContext.getBeanNamesForType(ResolvableType.forClassWithGenerics(Converter.class, String.class, typeClass)))
				.map(name -> name == null ? null : (Converter<String, Enum<?>>) applicationContext.getBean(name)).toList();

		for (var converter : converters) {
			if (httpMessagePossibleValues.size() > 0 && acceptsAll(converter, httpMessagePossibleValues)) {
				return schemaOf(httpMessagePossibleValues);
			}
		}

		// If there is no registered converter capable of deserializing the output of registered converters, use enum name()
		return schemaOf(namePossibleValues);

	}

	@SuppressWarnings("unchecked")
	private Set<String> getHttpMessagePossibleValuesFor(Class<Enum<?>> enumClass) {
		if (enumClass == null) {
			return Set.of();
		}
		// @formatter:off
		final var httpMessageConverters = Stream.of(applicationContext.getBeanNamesForType(HttpMessageConverter.class))
				.map(applicationContext::getBean)
				.map(HttpMessageConverter.class::cast)
				.filter(converter -> converter.getSupportedMediaTypes(enumClass).size() > 0)
				.toList();
		// @formatter:on
		if (httpMessageConverters.size() == 0) {
			return Set.of();
		}
		final var firstExtractor = EnumPossibleValuesExtractor.byHttpMessageConverter(httpMessageConverters.get(0));
		final var possibleValues = firstExtractor.getValues(enumClass);
		for (var i = 1; i < httpMessageConverters.size(); ++i) {
			final var other = EnumPossibleValuesExtractor.byHttpMessageConverter(httpMessageConverters.get(i)).getValues(enumClass);
			if (!possibleValues.equals(other)) {
				throw new RuntimeException(
						"%s and %s provide with different possible values for enum %s (%s VS %s). Can't build OpenAPI spec. Please uniformize enums serilaization accross HttpMessageConverters."
								.formatted(
										httpMessageConverters.get(0).getClass().getName(),
										httpMessageConverters.get(i).getClass().getName(),
										enumClass.getName(),
										possibleValues,
										other));
			}
		}
		return possibleValues;
	}

	private boolean acceptsAll(Converter<String, Enum<?>> converter, Collection<String> possibleValues) {
		for (var v : possibleValues) {
			if (v == null || converter.convert(v) == null) {
				return false;
			}
		}
		return true;
	}

	private StringSchema schemaOf(Collection<String> possibleValues) {
		final var schema = new StringSchema();
		possibleValues.forEach(schema::addEnumItem);
		return schema;
	}

	private static interface EnumPossibleValuesExtractor {

		Set<String> getValues(Class<Enum<?>> enumClass);

		static EnumPossibleValuesExtractor byName() {
			return enumClass -> Stream.of(enumClass.getEnumConstants()).map(Enum::name).collect(Collectors.toSet());
		}

		@SuppressWarnings("null")
		static EnumPossibleValuesExtractor byHttpMessageConverter(HttpMessageConverter<Object> converter) {
			return enumClass -> Stream.of(enumClass.getEnumConstants()).map(e -> {
				final var msg = new StubJsonHttpOutputMessage();
				try {
					converter.write(e, converter.getSupportedMediaTypes(enumClass).get(0), msg);
					final var serialized = msg.getBody().toString();
					if (serialized.startsWith("\"") && serialized.endsWith("\"")) {
						// at least Jackson serializes values with double quotes, strip it if present
						return serialized.substring(1, serialized.length() - 1);
					}
					return serialized;
				} catch (HttpMessageNotWritableException | IOException e1) {
					throw new RuntimeException(e1);
				}
			}).collect(Collectors.toSet());
		}
	}
}
