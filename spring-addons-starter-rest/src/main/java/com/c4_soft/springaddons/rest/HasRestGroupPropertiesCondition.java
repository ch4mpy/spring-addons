package com.c4_soft.springaddons.rest;

/**
 * Matches when "com.c4-soft.springaddons.rest.group" is a non-empty {@code Map}, that is, when at
 * least one {@code @ImportHttpServices} group is configured to back its proxies with an
 * auto-configured client.
 *
 * @author Jérôme Wacongne &lt;ch4mp&#64;c4-soft.com&gt;
 */
public class HasRestGroupPropertiesCondition extends HasPropertyPrefixCondition {

  public HasRestGroupPropertiesCondition() {
    super("com.c4-soft.springaddons.rest.group");
  }
}
