package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(classes = StubBootApplication.class)
@ActiveProfiles("std-env-vars")
class SpringAddonsClientHttpRequestFactoryStdEnvVarsTest
    extends AbstractSpringAddonsClientHttpRequestFactoryTest {

  @Test
  void test() throws IOException, IllegalArgumentException, IllegalAccessException,
      NoSuchFieldException, SecurityException {
    assertTrue(isUsingProxy("http://server.external.com/foo"));
    assertFalse(isUsingProxy("http://localhost/foo"));
    assertFalse(isUsingProxy("http://bravo-ch4mp/foo"));
    assertFalse(isUsingProxy("http://server.corporate-domain.pf/foo"));
  }
}
