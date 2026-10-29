package com.c4_soft.springaddons.security.oidc.starter;

import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.util.MultiValueMap;
import com.c4_soft.springaddons.security.oidc.starter.properties.SpringAddonsOidcClientProperties;

/**
 * Client properties counting how many times the extra token parameters are read, which the
 * per-registration providers do once per {@code refresh_token} provider they build, and holding
 * each read until the given number of reads overlap (or for one second): concurrent builds of the
 * providers of a registration then always overlap.
 */
public class BlockingClientProperties extends SpringAddonsOidcClientProperties {
  private final AtomicInteger extraTokenParametersReads = new AtomicInteger();
  private final CyclicBarrier overlappingReads;

  public BlockingClientProperties(int overlappingReads) {
    this.overlappingReads = new CyclicBarrier(overlappingReads);
  }

  public int extraTokenParametersReads() {
    return extraTokenParametersReads.get();
  }

  @Override
  public MultiValueMap<String, String> getExtraTokenParameters(String registrationId) {
    extraTokenParametersReads.incrementAndGet();
    try {
      overlappingReads.await(1, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (BrokenBarrierException | TimeoutException e) {
      // the reads did not overlap: the providers were built by a single request
    }
    return super.getExtraTokenParameters(registrationId);
  }
}
