package com.c4_soft.springaddons.rest.synchronised;

/**
 * Customizes the implementation-specific HTTP client builder just before the request factory is
 * built, for whatever is not exposed as a property. {@code B} is the builder of the configured
 * {@code client-http-request-factory-impl}: {@code java.net.http.HttpClient.Builder} (JDK),
 * {@code org.apache.hc.client5.http.impl.classic.HttpClientBuilder} (HttpComponents) or
 * {@code org.eclipse.jetty.client.HttpClient} (Jetty). Reference it per client with the
 * {@code http.request-factory-customizer-bean} property.
 */
@FunctionalInterface
public interface HttpClientCustomizer<B> {
  void customize(B builder);

  @SuppressWarnings({"unchecked", "rawtypes"})
  static void apply(Object customizer, Object builder) {
    if (customizer instanceof HttpClientCustomizer c) {
      c.customize(builder);
    }
  }
}
