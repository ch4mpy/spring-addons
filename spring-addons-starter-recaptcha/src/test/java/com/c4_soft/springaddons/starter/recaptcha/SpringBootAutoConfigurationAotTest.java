package com.c4_soft.springaddons.starter.recaptcha;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.aot.generate.ClassNameGenerator;
import org.springframework.aot.generate.DefaultGenerationContext;
import org.springframework.aot.generate.InMemoryGeneratedFiles;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.context.annotation.AnnotationConfigUtils;
import org.springframework.context.aot.ApplicationContextAotGenerator;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.javapoet.ClassName;

/**
 * The siteverify responses are bound by Jackson, through reflection: Spring AOT must register the
 * hints a native image needs for the response DTOs (gh-345).
 */
class SpringBootAutoConfigurationAotTest {

  @Test
  void givenAutoConfiguration_whenAotProcessed_thenResponseDtosAreRegisteredForBinding() {
    final var hints = processAheadOfTime();

    assertThat(hints).matches(RuntimeHintsPredicates.reflection()
        .onMethodInvocation(V2ValidationResponseDto.class, "setSuccess"));
    assertThat(hints).matches(RuntimeHintsPredicates.reflection()
        .onMethodInvocation(V2ValidationResponseDto.class, "setErrorCodes"));
    assertThat(hints).matches(
        RuntimeHintsPredicates.reflection().onFieldAccess(V2ValidationResponseDto.class, "errorCodes"));
    assertThat(hints).matches(RuntimeHintsPredicates.reflection()
        .onMethodInvocation(V3ValidationResponseDto.class, "setScore"));
    assertThat(hints).matches(RuntimeHintsPredicates.reflection()
        .onMethodInvocation(V3ValidationResponseDto.class, "setAction"));
  }

  private static RuntimeHints processAheadOfTime() {
    final var generationContext = new DefaultGenerationContext(
        new ClassNameGenerator(ClassName.get(SpringBootAutoConfigurationAotTest.class)),
        new InMemoryGeneratedFiles());
    try (final var context = new GenericApplicationContext()) {
      AnnotationConfigUtils.registerAnnotationConfigProcessors(context);
      context.registerBean(SpringBootAutoConfiguration.class);
      new ApplicationContextAotGenerator().processAheadOfTime(context, generationContext);
    }
    return generationContext.getRuntimeHints();
  }
}
