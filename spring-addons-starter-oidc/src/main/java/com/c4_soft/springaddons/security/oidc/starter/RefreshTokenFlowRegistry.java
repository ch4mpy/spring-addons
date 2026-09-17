package com.c4_soft.springaddons.security.oidc.starter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.util.Assert;

/**
 * <p>
 * Keeps track of the {@code refresh_token} flows which are currently running (or which recently
 * completed), so that concurrent requests needing the very same refresh can share a single token
 * request to the authorization server instead of each firing its own.
 * </p>
 * <p>
 * This is what makes it possible to work around a limitation of Spring Security: most authorization
 * servers rotate refresh tokens (the previous one is revoked when a new one is issued), which means
 * that when a user-agent sends parallel requests with an expired access token in session, all but
 * one of the concurrent refresh attempts fail, and the corresponding requests are answered with a
 * {@code 401}. See <a href=
 * "https://github.com/spring-projects/spring-security/issues/15145">spring-security#15145</a>.
 * </p>
 * <p>
 * Flows are keyed with a digest of everything which defines the token request to run: the client
 * registration ID, the principal name, the access and refresh token values, and the requested
 * scopes, if any. Two requests are de-duplicated if and only if they would send the exact same
 * payload to the token endpoint, which, with a session scoped
 * {@code (Server)OAuth2AuthorizedClientRepository}, means "requests from the same session". Requests
 * from different sessions have different refresh tokens and keep running in parallel.
 * </p>
 * <p>
 * A completed flow is kept for a short while so that a request which had loaded the authorized
 * client from the session just before the refreshed one was saved there gets the result of that
 * refresh instead of replaying a refresh token which is already spent.
 * </p>
 *
 * @param <T> what a leader shares with the requests joining its flow: a
 *        {@link java.util.concurrent.CompletableFuture} in a servlet application, a
 *        {@code reactor.core.publisher.Mono} in a reactive one.
 * @author Jerome Wacongne ch4mp&#64;c4-soft.com
 */
public final class RefreshTokenFlowRegistry<T> {

  private static final long EVICTION_PERIOD_MILLIS = 1000L;

  private final Clock clock;
  private final Duration maxFlowDuration;
  private final ConcurrentMap<String, Flow<T>> flows = new ConcurrentHashMap<>();
  private final AtomicLong nextEviction = new AtomicLong(Long.MIN_VALUE);

  /**
   * @param maxFlowDuration how long an entry is kept for a flow which never terminates. This is
   *        just a safety net against leaks: a flow which terminates sets its own retention with
   *        {@link Flow#terminated(Duration)}.
   * @param clock the clock to read the current time from
   */
  public RefreshTokenFlowRegistry(Duration maxFlowDuration, Clock clock) {
    Assert.notNull(maxFlowDuration, "maxFlowDuration cannot be null");
    Assert.notNull(clock, "clock cannot be null");
    this.maxFlowDuration = maxFlowDuration;
    this.clock = clock;
  }

  public RefreshTokenFlowRegistry(Duration maxFlowDuration) {
    this(maxFlowDuration, Clock.systemUTC());
  }

  /**
   * <p>
   * Either registers the caller as the leader of a new flow, or hands it the flow it should join.
   * </p>
   *
   * @param key as built by {@link #flowKey(OAuth2AuthorizationContext)}
   * @param payloadFactory builds what a leader shares with the requests joining its flow. It must
   *        have no side effect: it is also invoked by callers which end up joining an existing flow
   *        (the payload they built is then discarded).
   * @return the flow to run or to join
   */
  public Lease<T> acquire(String key, Function<Flow<T>, T> payloadFactory) {
    Assert.hasText(key, "key cannot be empty");
    evictExpiredIfDue();
    for (;;) {
      final var now = clock.millis();
      final var existing = flows.get(key);
      if (existing != null && !existing.isExpired(now)) {
        return new Lease<>(existing, false);
      }
      final var mine = new Flow<T>(clock, now + maxFlowDuration.toMillis());
      mine.payload = payloadFactory.apply(mine);
      final var won = existing == null ? flows.putIfAbsent(key, mine) == null
          : flows.replace(key, existing, mine);
      if (won) {
        return new Lease<>(mine, true);
      }
    }
  }

  /**
   * Drops a flow from this registry, so that it is not shared with any new request. To be called by
   * a leader for a flow whose outcome is not worth sharing (no token request was actually sent, for
   * instance).
   *
   * @param key the key the flow was acquired with
   * @param flow the flow to drop
   */
  public void release(String key, Flow<T> flow) {
    flows.remove(key, flow);
  }

  /**
   * @return the number of flows currently registered (running or recently completed). Exposed for
   *         tests and monitoring.
   */
  public int size() {
    return flows.size();
  }

  private void evictExpiredIfDue() {
    final var now = clock.millis();
    final var due = nextEviction.get();
    if (now < due || !nextEviction.compareAndSet(due, now + EVICTION_PERIOD_MILLIS)) {
      return;
    }
    flows.values().removeIf(flow -> flow.isExpired(now));
  }

  /**
   * <p>
   * Builds the key under which the {@code refresh_token} flow for the given context is registered:
   * a digest of everything which defines the token request to send.
   * </p>
   * <p>
   * Token values are hashed, not kept as-is, so that this registry does not hold clear-text token
   * material for longer than the authorized client itself lives.
   * </p>
   *
   * @param context the authorization context to run a {@code refresh_token} flow for. It must hold
   *        an authorized client with a refresh token.
   * @return the key to {@link #acquire(String, Function)} a flow with
   */
  public static String flowKey(OAuth2AuthorizationContext context) {
    Assert.notNull(context, "context cannot be null");
    final var authorizedClient = context.getAuthorizedClient();
    Assert.notNull(authorizedClient, "context must hold an authorized client");
    Assert.notNull(authorizedClient.getRefreshToken(),
        "the authorized client in the context must hold a refresh token");

    final MessageDigest digest;
    try {
      digest = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      // Every JRE is required to support SHA-256
      throw new IllegalStateException(e);
    }
    update(digest, context.getClientRegistration().getRegistrationId());
    update(digest, context.getPrincipal().getName());
    update(digest, authorizedClient.getAccessToken().getTokenValue());
    update(digest, authorizedClient.getRefreshToken().getTokenValue());

    final Object requestScope =
        context.getAttribute(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME);
    if (requestScope instanceof String[] scopes) {
      final var sorted = scopes.clone();
      Arrays.sort(sorted);
      for (var scope : sorted) {
        update(digest, scope);
      }
    }

    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
  }

  private static void update(MessageDigest digest, String value) {
    if (value != null) {
      digest.update(value.getBytes(StandardCharsets.UTF_8));
    }
    // Separator, so that concatenations of different values can't collide
    digest.update((byte) 0);
  }

  /**
   * A {@code refresh_token} flow, running or recently completed, shared by all the requests which
   * would otherwise send the very same token request.
   *
   * @param <T> what the leader shares with the requests joining the flow
   */
  public static final class Flow<T> {
    private final Clock clock;
    private volatile T payload;
    private volatile long expiresAt;

    private Flow(Clock clock, long expiresAt) {
      this.clock = clock;
      this.expiresAt = expiresAt;
    }

    /**
     * @return what the leader shares with the requests joining this flow
     */
    public T getPayload() {
      return payload;
    }

    /**
     * To be called by the leader when the flow terminates, to define how long its outcome is shared
     * with new requests.
     *
     * @param retention how long this flow is kept in the registry after it terminated
     */
    public void terminated(Duration retention) {
      this.expiresAt = clock.millis() + Math.max(0L, retention.toMillis());
    }

    private boolean isExpired(long nowMillis) {
      return nowMillis >= expiresAt;
    }
  }

  /**
   * The outcome of {@link RefreshTokenFlowRegistry#acquire(String, Function)}.
   *
   * @param <T> what the leader shares with the requests joining the flow
   * @param flow the flow to run (if leader) or to join
   * @param leader whether the caller is responsible for actually running the flow
   */
  public record Lease<T>(Flow<T> flow, boolean leader) {
  }
}
