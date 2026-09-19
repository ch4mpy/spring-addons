package com.c4_soft.springaddons.openapi;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.core.codec.Encoder;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.MediaType;
import org.springframework.http.codec.EncoderHttpMessageWriter;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.util.MimeType;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * <p>
 * {@link AbstractSpringEnumModelConverter} for reactive applications: body values are what the
 * JSON {@link Encoder}s of the {@link ServerCodecConfigurer} write, which is what WebFlux uses for
 * {@code @RequestBody} / {@code @ResponseBody}.
 * </p>
 *
 * @author ch4mp&#64;c4-soft.com
 * @see <a href=
 *      "https://docs.spring.io/spring-framework/reference/web/webflux/controller/ann-methods/typeconversion.html">Spring
 *      doc for types conversion</a>
 * @see <a href=
 *      "https://docs.spring.io/spring-framework/reference/web/webflux/reactive-spring.html#webflux-codecs">Spring
 *      doc for HTTP Message Conversion in reactive stack</a>
 */
public class SpringReactiveEnumModelConverter extends AbstractSpringEnumModelConverter {

  private final ApplicationContext applicationContext;

  public SpringReactiveEnumModelConverter(ApplicationContext applicationContext,
      Collection<? extends ConversionService> conversionServices,
      ObjectMapper springDocObjectMapper) {
    super(conversionServices, springDocObjectMapper);
    this.applicationContext = applicationContext;
  }

  @Override
  protected Collection<EnumPossibleValuesExtractor> writtenValuesExtractors(
      Class<Enum<?>> enumClass) {
    final var type = ResolvableType.forClass(enumClass);
    return encoders().filter(encoder -> jsonMimeType(encoder, type) != null)
        .map(encoder -> (EnumPossibleValuesExtractor) enumType -> constants(enumType)
            .map(e -> encode(encoder, jsonMimeType(encoder, type), type, e))
            .collect(toOrderedSet()))
        .toList();
  }

  @SuppressWarnings("unchecked")
  private Stream<Encoder<Object>> encoders() {
    return applicationContext.getBeanProvider(ServerCodecConfigurer.class).orderedStream()
        .map(ServerCodecConfigurer::getWriters).flatMap(List::stream)
        .filter(EncoderHttpMessageWriter.class::isInstance)
        .map(writer -> (Encoder<Object>) ((EncoderHttpMessageWriter<?>) writer).getEncoder())
        .distinct();
  }

  /**
   * @return the first JSON mime type the encoder can encode the enum as (the OpenAPI enum values
   *         describe JSON payloads), or null if there is none
   */
  private static MimeType jsonMimeType(Encoder<Object> encoder, ResolvableType type) {
    return encoder.getEncodableMimeTypes(type).stream()
        .filter(mimeType -> mimeType.isCompatibleWith(MediaType.APPLICATION_JSON)
            || mimeType.getSubtype().endsWith("+json"))
        .filter(mimeType -> encoder.canEncode(type, mimeType)).findFirst().orElse(null);
  }

  private static String encode(Encoder<Object> encoder, MimeType mimeType, ResolvableType type,
      Enum<?> constant) {
    final var buffer = encoder.encodeValue(constant, DefaultDataBufferFactory.sharedInstance,
        type, mimeType, Map.of());
    try {
      return stripQuotes(buffer.toString(StandardCharsets.UTF_8));
    } finally {
      DataBufferUtils.release(buffer);
    }
  }
}
