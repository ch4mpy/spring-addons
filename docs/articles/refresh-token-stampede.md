---
title: One refresh token flow at a time
parent: Articles
nav_order: 2
description: "Rotating refresh tokens plus parallel requests equals random 401s. Why Spring Security declined to fix it, how de-duplicating the refresh_token flow works, and what a cross-instance implementation has to get right."
---

# One refresh token flow at a time
{: .no_toc }

1. TOC
{:toc}

## The bug you will blame on something else

A user has a session on a Spring Boot OAuth2 client. The access token in that session has just expired. The page loads and fires five requests at once.

Spring Security sees five requests needing a fresh token and runs five `refresh_token` flows. The authorization server rotates refresh tokens, as Keycloak, Auth0 and most others do by default: the first flow succeeds and invalidates the refresh token it consumed, and the four others present a token which no longer exists. Four `401`s, and a user who was logged out for no reason they can describe.

Two things make this worse than it sounds. It needs no load at all: two requests sent within the duration of one token request are enough, which a single-page application refreshing a few widgets does constantly. And it is intermittent by construction, so it reaches production, where it reads as "users get randomly disconnected" and gets blamed on the session store, the load balancer, or the authorization server.

## Why Spring Security does not fix it

It was reported as [spring-security#15145](https://github.com/spring-projects/spring-security/issues/15145) and declined, as not something the framework can solve generally.

That is the right call, and it is worth understanding rather than resenting, because it defines what a fix has to look like. The framework does not know how sessions are stored. In one deployment the authorized client lives in an in-memory `HttpSession`, in another in Redis through Spring Session, in another in a JWT cookie. It does not know whether the application runs as one instance or forty, or whether the ingress has session affinity. A de-duplication which is correct in one of those is wrong or useless in the others, and a framework default which is sometimes wrong in the security layer is worse than no default.

What the framework can reasonably offer is the extension point, which it does: `OAuth2AuthorizedClientProvider` is an interface, and the provider chain is a bean.

## What the fix is

`spring-addons-starter-oidc` decorates the `RefreshToken(Reactive)OAuth2AuthorizedClientProvider` it builds with a `SingleRefreshTokenFlow(Reactive)OAuth2AuthorizedClientProvider`. The first request to reach the provider runs the flow. The others wait for its result. The authorization server sees one token request, and the refresh token is spent exactly once.

Stated that way it sounds like a five-line `ConcurrentHashMap.computeIfAbsent`. The interesting part is everything that is not the happy path.

### Keying on the request, not on the session

Flows are keyed with a digest of everything which defines the token request: the client registration ID, the principal name, the access and refresh token values, and the requested scopes if any.

The temptation is to key on the session ID, which is what the problem statement suggests. It is the wrong key twice over. The session ID is not available in the `OAuth2AuthorizationContext`, so getting it means reaching outside the abstraction. And it is not what correctness requires: two requests must share a flow if and only if they would send the same payload to the token endpoint. With a session-scoped authorized client repository that happens to mean "same session", which is why the session key looks right, but the token-request key is the one which stays right when the repository is not session-scoped.

### Sharing the outcome after the flow ends

This is the part which is not obvious until it bites. A request which loaded the authorized client from the session a millisecond before the refreshed one was written there holds the old refresh token, and arrives after the flow completed. If the result is discarded as soon as the flow ends, that request runs a second flow with a token which is already spent, and gets its `401` anyway.

So the result of a successful flow stays available for a short while, `PT10S` by default, well below any access token lifespan.

### Sharing failures too

Less intuitive, and more important. If a flow fails, letting every other waiting request retry means replaying a refresh token which the authorization server may have already rotated. Several authorization servers treat a replayed refresh token as a compromise indicator and revoke the entire token family, which turns a transient failure into a hard logout for that user. Failures are shared briefly for that reason, and it is configurable down to `PT0S` for an authorization server where that concern does not apply.

### Giving up with the right error

A request which waits past the timeout has to fail with something. `invalid_grant` would be the intuitive choice and is the wrong one: Spring Security's `RemoveAuthorizedClientOAuth2AuthorizationFailureHandler` reacts to it by evicting the authorized client from the session, and nothing here proved the refresh token invalid. The failure is `server_error`, which leaves the session intact for the next request to retry.

## Configuration

Defaults suit most applications, and none of this needs Java code:

```yaml
com:
  c4-soft:
    springaddons:
      oidc:
        client:
          single-refresh-token-flow:
            # false restores the Spring Security behavior, one flow per request
            enabled: true
            # how long a request waits for the flow it joined before giving up with server_error
            timeout: PT30S
            # how long the result of a successful flow is shared. Keep it well below the access token lifespan.
            success-caching-duration: PT10S
            # how long a failure is shared. PT0S makes each request run its own flow after a failure.
            error-caching-duration: PT10S
```

An application exposing its own `OAuth2AuthorizedClientProvider` keeps control by decorating the refresh provider itself:

```java
@Bean
OAuth2AuthorizedClientProvider oauth2AuthorizedClientProvider(SpringAddonsOidcProperties addonsProperties) {
  var refreshTokenProvider = new RefreshTokenOAuth2AuthorizedClientProvider();
  return new DelegatingOAuth2AuthorizedClientProvider(
      new AuthorizationCodeOAuth2AuthorizedClientProvider(),
      new SingleRefreshTokenFlowOAuth2AuthorizedClientProvider(
          refreshTokenProvider, addonsProperties.getClient().getSingleRefreshTokenFlow()));
}
```

## The honest limit: more than one JVM

De-duplication happens inside one JVM. Behind a load balancer without session affinity, parallel requests from one user-agent land on several instances, each runs its own flow, and the problem comes back divided by the number of instances rather than solved.

The answer to prefer is session affinity at the ingress. It removes the problem entirely, it costs nothing, and Spring Session still earns its keep for failover and rolling restarts. That is why spring-addons stops here rather than shipping a distributed implementation nobody asked for.

One trap deserves naming, because it is the first idea everyone has: Spring Session cannot be pressed into service as a distributed lock. `SessionRepository` exposes `createSession`, `save`, `findById` and `deleteById`, with no lock, no compare-and-swap and no version, so a "lock" written as a session attribute is a read-modify-write that two instances win at once. Its default `FlushMode` is `ON_SAVE`, so a refreshed authorized client only reaches the store when the holder's whole request ends, and `SessionRepositoryFilter` hands each request a snapshot it keeps reading. A lock built on it is not merely weak, it cannot observe the thing it is supposed to coordinate.

### If you do need cross-instance de-duplication

Write a decorator in place of `SingleRefreshTokenFlowOAuth2AuthorizedClientProvider` in the bean above, backed by whatever the cluster already runs. What the single-JVM implementation learned, which transfers:

- Key on the token request, not on the session, for the reasons above.
- Share the **outcome**, not just a lock. A lock alone leaves the other instances with nothing to read: they cannot get the result from the session, for the `FlushMode` and snapshot reasons above.
- Keep sharing that outcome for a few seconds after the flow completed, or the requests which loaded the client just before the write replay a spent token.
- Share failures too, briefly.
- Put an expiry on everything: a lease on the lock so an instance going down does not block the others, and a retention on the outcome so nothing outlives the tokens it holds.
- Store only the principal name and the tokens, never the `ClientRegistration`, whose serialization carries the client secret. Rebuild the `OAuth2AuthorizedClient` around the registration already in the context.
- Treat a store failure as a miss: log it and run the flow locally. Degrading to one flow per instance is no worse than having no store, and much better than failing authorization.
- Raise `server_error`, not `invalid_grant`, when a request gives up waiting.

## Why this is worth a page

Most of what a starter does is save typing. This is the other kind: a defect with a plausible wrong explanation, in a place where the framework has deliberately declined to take a position, whose fix is twenty lines of obvious code plus four caveats that are only obvious in hindsight.

The reference is on the [clients page]({{ site.baseurl }}/oidc/client/#concurrent-refresh-token-flows). It shipped in spring-addons 9.3.1.
