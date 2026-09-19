package com.c4_soft.springaddons.openapi;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.ConversionService;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * <p>
 * {@link AbstractSpringEnumModelConverter} for servlet applications: body values are what the
 * {@link HttpMessageConverter}s of the {@link RequestMappingHandlerAdapter} write, which is the
 * list Spring MVC actually uses for {@code @RequestBody} / {@code @ResponseBody} (Spring Boot 4
 * does not expose individual converters as beans anymore). {@link HttpMessageConverter} beans, if
 * any, are considered too.
 * </p>
 *
 * @author ch4mp&#64;c4-soft.com
 * @see <a href=
 *      "https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/typeconversion.html">Spring
 *      doc for types conversion</a>
 * @see <a href=
 *      "https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/requestbody.html">Spring
 *      doc for HTTP Message Conversion</a>
 */
public class SpringServletEnumModelConverter extends AbstractSpringEnumModelConverter {

  private final ApplicationContext applicationContext;

  public SpringServletEnumModelConverter(ApplicationContext applicationContext,
      Collection<? extends ConversionService> conversionServices,
      ObjectMapper springDocObjectMapper) {
    super(conversionServices, springDocObjectMapper);
    this.applicationContext = applicationContext;
  }

  @Override
  protected Collection<EnumPossibleValuesExtractor> writtenValuesExtractors(
      Class<Enum<?>> enumClass) {
    return messageConverters().filter(converter -> jsonMediaType(converter, enumClass) != null)
        .map(converter -> (EnumPossibleValuesExtractor) enumType -> constants(enumType)
            .map(e -> write(converter, jsonMediaType(converter, enumType), e))
            .collect(toOrderedSet()))
        .toList();
  }

  @SuppressWarnings("unchecked")
  private Stream<HttpMessageConverter<Object>> messageConverters() {
    final Stream<HttpMessageConverter<?>> fromHandlerAdapters =
        applicationContext.getBeanProvider(RequestMappingHandlerAdapter.class).orderedStream()
            .map(RequestMappingHandlerAdapter::getMessageConverters).flatMap(List::stream);
    final Stream<HttpMessageConverter<?>> beans =
        applicationContext.getBeanProvider(HttpMessageConverter.class).orderedStream()
            .map(converter -> (HttpMessageConverter<?>) converter);
    return Stream.concat(fromHandlerAdapters, beans).distinct()
        .map(converter -> (HttpMessageConverter<Object>) converter);
  }

  /**
   * @return the first JSON media type the converter can write the enum as (the OpenAPI enum values
   *         describe JSON payloads), or null if there is none
   */
  private static MediaType jsonMediaType(HttpMessageConverter<Object> converter,
      Class<Enum<?>> enumClass) {
    return converter.getSupportedMediaTypes(enumClass).stream()
        .filter(mediaType -> mediaType.isCompatibleWith(MediaType.APPLICATION_JSON)
            || mediaType.getSubtype().endsWith("+json"))
        .filter(mediaType -> converter.canWrite(enumClass, mediaType)).findFirst().orElse(null);
  }

  private static String write(HttpMessageConverter<Object> converter, MediaType mediaType,
      Enum<?> constant) {
    final var msg = new MockHttpOutputMessage();
    try {
      converter.write(constant, mediaType, msg);
      return stripQuotes(msg.getBodyAsString());
    } catch (HttpMessageNotWritableException | IOException e) {
      throw new IllegalStateException(
          "%s could not write %s.%s".formatted(converter.getClass().getName(),
              constant.getDeclaringClass().getName(), constant.name()),
          e);
    }
  }
}
