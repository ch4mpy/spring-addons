package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(classes = StubBootApplication.class)
@ActiveProfiles("minimal")
class SpringAddonsClientHttpRequestFactoryMinimalTest
    extends AbstractSpringAddonsClientHttpRequestFactoryTest {

  @Test
  void test() throws IOException, IllegalArgumentException, IllegalAccessException,
      NoSuchFieldException, SecurityException {
    assertTrue(isUsingProxy("http://server.external.com/foo"));
    assertTrue(isUsingProxy("http://localhost/foo"));
    assertTrue(isUsingProxy("http://bravo-ch4mp/foo"));
    assertTrue(isUsingProxy("http://server.corporate-domain.pf/foo"));
  }
}
