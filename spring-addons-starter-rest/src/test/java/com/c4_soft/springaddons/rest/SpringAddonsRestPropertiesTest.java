package com.c4_soft.springaddons.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestClientProperties;
import com.c4_soft.springaddons.rest.SpringAddonsRestProperties.RestGroupProperties;

class SpringAddonsRestPropertiesTest {

  @Test
  void givenGroupReferencesAConfiguredClient_whenGetGroupClientId_thenClientId() {
    final var properties = new SpringAddonsRestProperties();
    properties.getClient().put("foo-client", new RestClientProperties());
    final var group = new RestGroupProperties();
    group.setClient("foo-client");
    properties.getGroup().put("foo", group);

    assertThat(properties.getGroupClientId("foo")).isEqualTo("foo-client");
  }

  @Test
  void givenGroupHasNoClient_whenGetGroupClientId_thenMisconfigurationNamesTheProperty() {
    final var properties = new SpringAddonsRestProperties();
    properties.getGroup().put("foo", new RestGroupProperties());

    assertThatThrownBy(() -> properties.getGroupClientId("foo"))
        .isInstanceOf(RestMisconfigurationException.class)
        .hasMessageContaining("com.c4-soft.springaddons.rest.group.foo.client");
  }

  @Test
  void givenGroupReferencesAnUnknownClient_whenGetGroupClientId_thenMisconfigurationNamesTheClient() {
    final var properties = new SpringAddonsRestProperties();
    final var group = new RestGroupProperties();
    group.setClient("nope");
    properties.getGroup().put("foo", group);

    assertThatThrownBy(() -> properties.getGroupClientId("foo"))
        .isInstanceOf(RestMisconfigurationException.class).hasMessageContaining("'nope'");
  }

  @Test
  void givenMalformedBaseUrl_whenGetBaseUrl_thenMisconfigurationNamesTheValue() {
    final var client = new RestClientProperties();
    client.setBaseUrl(Optional.of("not a url"));

    assertThatThrownBy(client::getBaseUrl).isInstanceOf(RestMisconfigurationException.class)
        .hasMessageContaining("not a url");
  }

  @Test
  void givenClientIds_whenGetClientBeanName_thenCamelCaseWithOptionalBuilderSuffix() {
    final var properties = new SpringAddonsRestProperties();
    properties.getClient().put("foo-client", new RestClientProperties());
    final var builderClient = new RestClientProperties();
    builderClient.setExposeBuilder(true);
    properties.getClient().put("bar_client", builderClient);
    final var namedClient = new RestClientProperties();
    namedClient.setBeanName(Optional.of("custom"));
    properties.getClient().put("baz-client", namedClient);

    assertThat(properties.getClientBeanName("foo-client")).isEqualTo("fooClient");
    assertThat(properties.getClientBeanName("bar_client")).isEqualTo("barClientBuilder");
    assertThat(properties.getClientBeanName("baz-client")).isEqualTo("custom");
    assertThat(properties.getClientBeanName("unknown")).isNull();
  }
}
