package com.c4_soft.springaddons.rest;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.lang.Nullable;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.invoker.HttpExchangeAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;
import lombok.NoArgsConstructor;

/**
 * Bean factory using {@link HttpServiceProxyFactory} to generate an instance of a
 * {@link HttpExchange &#64;HttpExchange} interface
 * 
 * @param <T> {@link HttpExchange &#64;HttpExchange} interface to implement
 * @see WebClientHttpExchangeProxyFactoryBean WebClientHttpExchangeProxyFactoryBean for an
 *      equivalent accepting only WebClient
 * @see HttpExchangeProxyFactoryBean HttpExchangeProxyFactoryBean for an equivalent accepting both
 *      RestClient an WebClient
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
@NoArgsConstructor
public class RestClientHttpExchangeProxyFactoryBean<T> implements FactoryBean<T> {
  private Class<T> httpExchangeClass;
  private HttpExchangeAdapter adapter;

  public RestClientHttpExchangeProxyFactoryBean(Class<T> httpExchangeClass, RestClient client) {
    this.httpExchangeClass = httpExchangeClass;
    this.setClient(client);
  }

  @Override
  @Nullable
  public T getObject() throws Exception {
    if (adapter == null || getObjectType() == null) {
      throw new RestMisconfigurationException(
          "Both of a RestClient and the @HttpExchange interface to implement must be configured on the HttpExchangeProxyFactoryBean before calling the getObject() method.");
    }
    return HttpServiceProxyFactory.builderFor(adapter).build().createClient(getObjectType());
  }

  @Override
  public Class<T> getObjectType() {
    return httpExchangeClass;
  }

  public RestClientHttpExchangeProxyFactoryBean<T> setHttpExchangeClass(
      Class<T> httpExchangeClass) {
    this.httpExchangeClass = httpExchangeClass;
    return this;
  }

  public RestClientHttpExchangeProxyFactoryBean<T> setClient(RestClient client) {
    this.adapter = RestClientAdapter.create(client);
    return this;
  }

}
