package com.c4_soft.springaddons.openapi;

import java.lang.annotation.Annotation;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.core.convert.ConversionService;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.MatrixVariable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import io.swagger.v3.core.converter.AnnotatedType;
import io.swagger.v3.core.converter.ModelConverter;
import io.swagger.v3.core.converter.ModelConverterContext;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import lombok.extern.slf4j.Slf4j;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * <p>
 * A Swagger {@link ModelConverter} producing, for enums, the possible values that a Spring
 * application actually accepts and emits, instead of what {@code swagger-core} guesses from the
 * enum class.
 * </p>
 * <p>
 * Spring never uses {@code swagger-core} to (de)serialize enums:
 * </p>
 * <ul>
 * <li>{@link RequestParam &#64;RequestParam}, {@link PathVariable &#64;PathVariable},
 * {@link RequestHeader &#64;RequestHeader}, {@link CookieValue &#64;CookieValue} and
 * {@link MatrixVariable &#64;MatrixVariable} go through the {@link ConversionService}: by default
 * {@code Enum.valueOf(name())}, or any registered {@code Converter<String, E>}</li>
 * <li>{@link RequestBody &#64;RequestBody} and {@link ResponseBody &#64;ResponseBody} go through
 * the HTTP message converters (servlet) or codecs (reactive): Jackson by default, with whatever
 * {@code @JsonValue}, {@code @JsonProperty} or {@code EnumFeature} configuration applies</li>
 * </ul>
 * <p>
 * The schema of an enum is resolved as a parameter when the context annotations hold one of the
 * parameter annotations above, and as a body property otherwise.
 * </p>
 *
 * @author ch4mp&#64;c4-soft.com
 */
@Slf4j
public abstract class AbstractSpringEnumModelConverter implements ModelConverter {

  private static final Set<Class<? extends Annotation>> PARAMETER_ANNOTATIONS = Set.of(
      RequestParam.class, PathVariable.class, RequestHeader.class, CookieValue.class,
      MatrixVariable.class);

  private final Collection<? extends ConversionService> conversionServices;
  private final ObjectMapper springDocObjectMapper;

  protected AbstractSpringEnumModelConverter(
      Collection<? extends ConversionService> conversionServices,
      ObjectMapper springDocObjectMapper) {
    this.conversionServices = conversionServices;
    this.springDocObjectMapper = springDocObjectMapper;
  }

  @SuppressWarnings("unchecked")
  @Override
  public Schema<?> resolve(AnnotatedType type, ModelConverterContext context,
      Iterator<ModelConverter> chain) {
    final var javaType = springDocObjectMapper.constructType(type.getType());
    if (javaType == null || !javaType.isEnumType()) {
      return chain.hasNext() ? chain.next().resolve(type, context, chain) : null;
    }
    final var enumClass = (Class<Enum<?>>) javaType.getRawClass();

    final var values = isParameter(type) ? parameterValues(enumClass) : bodyValues(enumClass);
    final var schema = new StringSchema();
    values.forEach(schema::addEnumItem);
    return schema;
  }

  /**
   * @param enumClass an enum type
   * @return the values written by each of the HTTP message converters (or codecs) able to write
   *         that enum as JSON, as {@link EnumPossibleValuesExtractor}s. Empty if none was found.
   */
  protected abstract Collection<EnumPossibleValuesExtractor> writtenValuesExtractors(
      Class<Enum<?>> enumClass);

  private static boolean isParameter(AnnotatedType type) {
    final var annotations = type.getCtxAnnotations();
    return annotations != null && Stream.of(annotations)
        .anyMatch(a -> PARAMETER_ANNOTATIONS.contains(a.annotationType()));
  }

  /**
   * @return the values a {@code @RequestBody} accepts and a {@code @ResponseBody} emits: the
   *         output of the HTTP message converters, or of the springdoc {@link ObjectMapper} when
   *         no converter is available (a non-web application, for instance)
   */
  protected Set<String> bodyValues(Class<Enum<?>> enumClass) {
    final var written = writtenValues(enumClass);
    return written.isEmpty() ? jacksonValues(enumClass) : written;
  }

  /**
   * <p>
   * {@link ConversionService} converters work one way and nothing guarantees that
   * {@code Converter<E, String>} and {@code Converter<String, E>} are bijective. The best that can
   * be done is trying candidate sets of serialized values and keeping the first one that the
   * conversion service converts back to each enum constant.
   * </p>
   *
   * @return the values a {@code @RequestParam} (or path variable, header, cookie, matrix
   *         variable) accepts, tried in this order: what HTTP message converters write, what
   *         {@code toString()} returns, and enum {@code name()}s (which is what Spring's default
   *         {@code StringToEnumConverterFactory} expects)
   */
  protected Set<String> parameterValues(Class<Enum<?>> enumClass) {
    final var names = constants(enumClass).map(Enum::name).collect(toOrderedSet());
    final var candidates = List.of(writtenValues(enumClass),
        constants(enumClass).map(Enum::toString).collect(toOrderedSet()), names);
    return candidates.stream().filter(values -> !values.isEmpty())
        .filter(values -> roundTrips(values, enumClass)).findFirst().orElse(names);
  }

  private Set<String> writtenValues(Class<Enum<?>> enumClass) {
    final var extractors = writtenValuesExtractors(enumClass).iterator();
    if (!extractors.hasNext()) {
      return Set.of();
    }
    final var first = extractors.next();
    final var values = first.getValues(enumClass);
    while (extractors.hasNext()) {
      final var other = extractors.next();
      final var otherValues = other.getValues(enumClass);
      if (!values.equals(otherValues)) {
        throw new IllegalStateException(
            "%s and %s write different values for enum %s (%s VS %s). Can't build OpenAPI spec. Please make enum serialization consistent across HTTP message converters."
                .formatted(first.getClass().getName(), other.getClass().getName(),
                    enumClass.getName(), values, otherValues));
      }
    }
    return values;
  }

  private Set<String> jacksonValues(Class<Enum<?>> enumClass) {
    log.debug(
        "No HTTP message converter found for {}, using springdoc ObjectMapper to serialize its constants",
        enumClass.getName());
    return constants(enumClass).map(e -> {
      try {
        return stripQuotes(springDocObjectMapper.writeValueAsString(e));
      } catch (JsonProcessingException ex) {
        throw new IllegalStateException(ex);
      }
    }).collect(toOrderedSet());
  }

  private boolean roundTrips(Set<String> values, Class<Enum<?>> enumClass) {
    final var constants = constants(enumClass).collect(toOrderedSet());
    if (values.size() != constants.size()) {
      return false;
    }
    final var conversionService = conversionServices.stream()
        .filter(cs -> cs.canConvert(String.class, enumClass)).findFirst();
    if (conversionService.isEmpty()) {
      return false;
    }
    final var converted = values.stream().map(v -> {
      try {
        return (Enum<?>) conversionService.get().convert(v, enumClass);
      } catch (RuntimeException e) {
        log.debug("{} is not a valid input for {}: {}", v, enumClass.getName(), e.getMessage());
        return null;
      }
    }).filter(Objects::nonNull).collect(toOrderedSet());
    return converted.equals(constants);
  }

  /**
   * @param serialized a value as written by a JSON converter
   * @return the value without surrounding double quotes (Jackson writes enums as JSON strings)
   */
  protected static String stripQuotes(String serialized) {
    final var trimmed = serialized.trim();
    if (trimmed.length() >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
      return trimmed.substring(1, trimmed.length() - 1);
    }
    return trimmed;
  }

  protected static Stream<Enum<?>> constants(Class<Enum<?>> enumClass) {
    return Stream.of(enumClass.getEnumConstants());
  }

  protected static <T> java.util.stream.Collector<T, ?, Set<T>> toOrderedSet() {
    return Collectors.toCollection(LinkedHashSet::new);
  }
}
