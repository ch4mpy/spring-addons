package com.c4_soft.springaddons.openapi;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springdoc.core.providers.ObjectMapperProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.jspecify.annotations.NonNull;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import io.swagger.v3.core.converter.AnnotatedType;
import io.swagger.v3.core.converter.ModelConverter;
import io.swagger.v3.core.converter.ModelConverterContext;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * <p>
 * A Swagger {@link ModelConverter} to produce decent possible enum values in the OpenAPI spec of Spring applications.
 * </p>
 * The values are generated differently depending on the enum being:
 * <ul>
 * <li>part of a {@link RequestBody &#64;RequestBody} or {@link ResponseBody &#64;ResponseBody}: use {@link HttpMessageWriter}</li>
 * <li>a {@link RequestParam &#64;RequestParam}, {@link RequestHeader &#64;RequestHeader}, {@link PathVariable &#64;PathVariable},
 * {@link MatrixVariable &#64;MatrixVariable}and {@link CookieValue &#64;CookieValue} use the {@link FormattingConversionService}. If none
 * is found, use the enum name() (which is what the default converter does). If a custom converter is registered as a bean, then try to give
 * it as input in the following order: the Jackson converter output, the value of toString() and enum name()</li>
 * </ul>
 * 
 * @author ch4mp&#64;c4-soft.com
 * @see    <a href="https://docs.spring.io/spring-framework/reference/web/webflux/controller/ann-methods/typeconversion.html">Spring doc for
 *         types conversion</a>
 * @see    <a href="https://docs.spring.io/spring-framework/reference/web/webflux/reactive-spring.html#webflux-codecs">Spring doc for HTTP
 *         Message Conversion in reactive stack</a>
 */
@RequiredArgsConstructor
@Slf4j
public class SpringReactiveEnumModelConverter implements ModelConverter {

	private final ApplicationContext applicationContext;
	private final FormattingConversionService formattingConversionService;
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
		final var httpMessagePossibleWrittenValues = getHttpMessagePossibleWrittenValuesFor(enumClass);
		final var formattedPossibleValues = Stream.of(enumClass.getEnumConstants()).map(e -> formattingConversionService.convert(e, String.class)).toList();

		if (context.getDefinedModels().size() > 0 && httpMessagePossibleWrittenValues.size() > 0) {
			// Case of an enum part of a @RequestBody or @ResponseBody: use HttpMessageConverter::write
			return schemaOf(httpMessagePossibleWrittenValues);
		}

		// Case of an enum as @RequestParam, @RequestHeader, @PathVariable, @MatrixVariable, and @CookieValue

		// FormattingConversionService provides with converters working only one way and there is no guaranty that Converter<E, String> and
		// Converter<String, E> are bijective

		// So, to find the the possible inputs for Converter<String, E>, the best we can do is trying the different possible collections of
		// serialized values we have for an enum (using the formatter from FormattingConversionService or or the HttpMessageConverter) and select
		// the 1st for which all values are successfully deserialized
		if (httpMessagePossibleWrittenValues.size() > 0 && formattingConversionServiceAcceptsAll(httpMessagePossibleWrittenValues, enumClass)) {
			return schemaOf(httpMessagePossibleWrittenValues);
		}

		// If the output of HttpMessageConverter can't be deserialized using FormattingConversionService, use the output of
		// FormattingConversionService serialization
		return schemaOf(formattedPossibleValues);

	}

	private Set<String> getHttpMessagePossibleWrittenValuesFor(Class<Enum<?>> enumClass) {
		if (enumClass == null) {
			return Set.of();
		}

		final var extractors = getWrittingExtractorsFor(enumClass).iterator();
		if (!extractors.hasNext()) {
			return Set.of();
		}
		final var firstExtractor = extractors.next();
		final var possibleValues = firstExtractor.getValues(enumClass);
		log.info("possibleValues: {} {}", firstExtractor.getClass().getName(), possibleValues);
		while (extractors.hasNext()) {
			final var otherExtractor = extractors.next();
			final var other = otherExtractor.getValues(enumClass);
			log.info("possibleValues: {} {}", otherExtractor.getClass().getName(), other);
			if (!possibleValues.equals(other)) {
				throw new RuntimeException(
						"%s and %s provide with different possible values for enum %s (%s VS %s). Can't build OpenAPI spec. Please uniformize enums serilaization accross HttpMessageConverters."
								.formatted(
										firstExtractor.getClass().getName(),
										otherExtractor.getClass().getName(),
										enumClass.getName(),
										possibleValues,
										other));
			}
		}
		return possibleValues;
	}

	private Stream<HttpMessageWriter<?>> getConvertersFor(Class<Enum<?>> enumClass) {
		if (enumClass == null) {
			return Stream.empty();
		}
		final var type = ResolvableType.forClass(enumClass);
		// @formatter:off
		return Stream.of(applicationContext.getBeanNamesForType(ResolvableType.forClass(ServerCodecConfigurer.class)))
				.map(applicationContext::getBean)
				.map(ServerCodecConfigurer.class::cast)
				.map(ServerCodecConfigurer::getWriters)
				.flatMap(List::stream)
				.filter(converter -> converter.getWritableMediaTypes(type).stream().anyMatch(mediaType -> converter.canWrite(type,mediaType)))
				.map(writer -> {
					System.out.println("writer: %s".formatted(writer.getClass()));
					return (HttpMessageWriter<?>) writer;
				});
		// @formatter:on
	}

	private Collection<EnumPossibleValuesExtractor> getWrittingExtractorsFor(Class<Enum<?>> enumClass) {
		return getConvertersFor(enumClass).map(SpringReactiveEnumModelConverter::toWrittingExtractor).toList();
	}

	@SuppressWarnings("null")
	private static EnumPossibleValuesExtractor toWrittingExtractor(HttpMessageWriter<?> converter) {
		return enumClass -> Stream.of(enumClass.getEnumConstants()).map(e -> {
			final var type = ResolvableType.forClass(enumClass);
			// FIXME: create a "blockable" ServerHttpResponse to read the msg after it was written and extract the serialized value
			final ServerHttpResponse msg = null;
			((HttpMessageWriter<Object>) converter).write(
					Mono.just(e),
					type,
					converter.getWritableMediaTypes(type).stream().filter(mediaType -> converter.canWrite(type, mediaType)).findAny().get(),
					msg,
					Map.of()).block();
			final var serialized = "";

			if (serialized.startsWith("\"") && serialized.endsWith("\"")) {
				// at least Jackson serializes values with double quotes, strip it if present
				return serialized.substring(1, serialized.length() - 1);
			}
			return serialized;
		}).collect(Collectors.toSet());
	}

	private boolean formattingConversionServiceAcceptsAll(Collection<String> possibleValues, @NonNull Class<Enum<?>> enumClass) {
		for (var v : possibleValues) {
			try {
				if (formattingConversionService.convert(v, enumClass) == null) {
					return false;
				}
			} catch (Exception e) {
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
}
