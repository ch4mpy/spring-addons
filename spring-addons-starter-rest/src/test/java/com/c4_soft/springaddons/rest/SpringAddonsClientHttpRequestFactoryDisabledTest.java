package com.c4_soft.springaddons.rest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(classes = StubBootApplication.class)
@ActiveProfiles("proxy-disabled")
class SpringAddonsClientHttpRequestFactoryDisabledTest
    extends AbstractSpringAddonsClientHttpRequestFactoryTest {

  @Test
  void test() throws IOException, IllegalArgumentException, IllegalAccessException,
      NoSuchFieldException, SecurityException {
    assertFalse(isUsingProxy("http://server.external.com/foo"));
    assertFalse(isUsingProxy("http://localhost/foo"));
    assertFalse(isUsingProxy("http://bravo-ch4mp/foo"));
    assertFalse(isUsingProxy("http://server.corporate-domain.pf/foo"));
  }

}
