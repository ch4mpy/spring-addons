package com.c4_soft.springaddons.openapi;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springdoc.core.providers.ObjectMapperProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.lang.NonNull;
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

/**
 * <p>
 * A Swagger {@link ModelConverter} to produce decent possible enum values in the OpenAPI spec of
 * Spring applications.
 * </p>
 * The values are generated differently depending on the enum being:
 * <ul>
 * <li>part of a {@link RequestBody &#64;RequestBody} or {@link ResponseBody &#64;ResponseBody}: use
 * {@link HttpMessageConverter}</li>
 * <li>a {@link RequestParam &#64;RequestParam}, {@link RequestHeader &#64;RequestHeader},
 * {@link PathVariable &#64;PathVariable}, {@link MatrixVariable &#64;MatrixVariable}and
 * {@link CookieValue &#64;CookieValue} use the {@link FormattingConversionService}. If none is
 * found, use the enum name() (which is what the default converter does). If a custom converter is
 * registered as a bean, then try to give it as input in the following order: the Jackson converter
 * output, the value of toString() and enum name()</li>
 * </ul>
 * 
 * @author ch4mp&#64;c4-soft.com
 * @see <a href=
 *      "https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/typeconversion.html">Spring
 *      doc for types conversion</a>
 * @see <a href=
 *      "https://docs.spring.io/spring-framework/reference/integration/rest-clients.html#rest-message-conversion">Spring
 *      doc for HTTP Message Conversion</a>
 */
@RequiredArgsConstructor
public class SpringServletEnumModelConverter implements ModelConverter {

  private final ApplicationContext applicationContext;
  private final Collection<FormattingConversionService> formattingConversionServices;
  private final ObjectMapperProvider springDocObjectMapper;

  @SuppressWarnings("unchecked")
  @Override
  public Schema<?> resolve(AnnotatedType type, ModelConverterContext context,
      Iterator<ModelConverter> chain) {

    final var mapper = springDocObjectMapper.jsonMapper();
    final var javaType = mapper.constructType(type.getType());

    if (javaType == null || !javaType.isEnumType()) {
      return chain.hasNext() ? chain.next().resolve(type, context, chain) : null;
    }

    final var enumClass = (Class<Enum<?>>) javaType.getRawClass();
    final var httpMessagePossibleWrittenValues = getHttpMessagePossibleWrittenValuesFor(enumClass);

    if (context.getDefinedModels().size() > 0 && httpMessagePossibleWrittenValues.size() > 0) {
      // Case of an enum part of a @RequestBody or @ResponseBody: use HttpMessageConverter::write
      return schemaOf(httpMessagePossibleWrittenValues);
    }

    // Case of an enum as @RequestParam, @RequestHeader, @PathVariable, @MatrixVariable, and
    // @CookieValue

    // FormattingConversionService provides with converters working only one way and there is no
    // guaranty that Converter<E, String> and
    // Converter<String, E> are bijective

    // So, to find the the possible inputs for Converter<String, E>, the best we can do is trying
    // the different possible collections of
    // serialized values we have for an enum (using the formatter from FormattingConversionService
    // or or the HttpMessageConverter) and select
    // the 1st for which all values are successfully deserialized
    final var formattingConversionService = resolveConverterFor(enumClass);

    if (httpMessagePossibleWrittenValues.size() > 0 && formattingConversionService.isPresent()
        && formattingConversionServiceAcceptsAll(formattingConversionService.get(),
            httpMessagePossibleWrittenValues, enumClass)) {
      return schemaOf(httpMessagePossibleWrittenValues);
    }

    // If the output of HttpMessageConverter can't be deserialized using
    // FormattingConversionService, use the output of
    // FormattingConversionService serialization
    return schemaOf(Stream.of(enumClass.getEnumConstants())
        .map(e -> formattingConversionService.flatMap(fcs -> {
          final var converted = fcs.convert(e, String.class);
          return Optional.ofNullable(converted);
        }).orElse(e.toString())).toList());
  }

  private Optional<FormattingConversionService> resolveConverterFor(Class<Enum<?>> enumClass) {
    return formattingConversionServices.stream()
        .filter(fcs -> fcs.canConvert(enumClass, String.class)).findAny();
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
    while (extractors.hasNext()) {
      final var otherExtractor = extractors.next();
      final var other = otherExtractor.getValues(enumClass);
      if (!possibleValues.equals(other)) {
        throw new RuntimeException(
            "%s and %s provide with different possible values for enum %s (%s VS %s). Can't build OpenAPI spec. Please uniformize enums serilaization accross HttpMessageConverters."
                .formatted(firstExtractor.getClass().getName(), otherExtractor.getClass().getName(),
                    enumClass.getName(), possibleValues, other));
      }
    }
    return possibleValues;
  }

  @SuppressWarnings("unchecked")
  private Stream<HttpMessageConverter<Object>> getConvertersFor(Class<Enum<?>> enumClass) {
    if (enumClass == null) {
      return Stream.empty();
    }
    // @formatter:off
		return Stream.of(applicationContext.getBeanNamesForType(ResolvableType.forClassWithGenerics(HttpMessageConverter.class, Object.class)))
				.map(name -> (HttpMessageConverter<Object>) applicationContext.getBean(name))
				.filter(converter -> converter.getSupportedMediaTypes(enumClass)
						.stream()
						.anyMatch(mediaType -> converter.canWrite(enumClass, mediaType)));
		// @formatter:on
  }

  private Collection<EnumPossibleValuesExtractor> getWrittingExtractorsFor(
      Class<Enum<?>> enumClass) {
    return getConvertersFor(enumClass).map(SpringServletEnumModelConverter::toWrittingExtractor)
        .toList();
  }

  @SuppressWarnings("null")
  private static EnumPossibleValuesExtractor toWrittingExtractor(
      HttpMessageConverter<Object> converter) {
    return enumClass -> Stream.of(enumClass.getEnumConstants()).map(e -> {
      final var msg = new MockHttpOutputMessage();
      try {
        converter.write(e,
            converter.getSupportedMediaTypes(enumClass).stream()
                .filter(mediaType -> converter.canWrite(enumClass, mediaType)).findAny().get(),
            msg);
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

  private boolean formattingConversionServiceAcceptsAll(
      FormattingConversionService formattingConversionService, Collection<String> possibleValues,
      @NonNull Class<Enum<?>> enumClass) {
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
