---
title: Risks, in both directions
parent: spring-addons-starter-oidc
nav_order: 5
description: "What can go wrong when depending on a third-party Spring Security starter, and how to protect against each case. And what goes wrong when writing the same configuration by hand, which is the other half of the decision. Every auto-configured bean is @ConditionalOnMissingBean, so opting out is incremental."
---

# Risks, in both directions
{: .no_toc }

A dependency in the security layer deserves a page on what can go wrong with it. That page would be dishonest if it only listed the risks of taking the dependency: the alternative is not "no risk", it is a hand-written Spring Security configuration, which has failure modes of its own. Both halves are below.

1. TOC
{:toc}

## The risks of using these libs

Neither the owner of this repo nor any of the contributors are part of Spring Security team. At best, some are occasional contributors to the "official" framework.

However, unless you have a deep knowledge of Spring Security for OAuth2, using `spring-addons-starter-oidc` might actually be safer than experimenting with the conf by yourself. And the more popularity this repo gets, the safer it is: more people detect potential issues, more people can keep it alive if its initiator disappears and, if some features where to become popular enough, Spring team could consider pulling it in the official framework.

Also, all you have to do to opt-out `spring-addons-starter-oidc` at any point in time is writing Spring Security configuration by yourself: each of the auto-configured beans is `@ConditionalOnMissingBean`, so you can take back one of them at a time, and eventually the whole `Security(Web)FilterChain`, with just `spring-boot-starter-oauth2-client` or `spring-boot-starter-oauth2-resource-server`. [What you would write without spring-addons]({{ site.baseurl }}/without-spring-addons/) names each bean and its hand-written equivalent.

What are the identified risks of using the resources from such a repo and how can you protect against it?
- *what if the updates to latest dependencies stop and no PR are merged anymore?* You can fork this repo and start a new branch from the last tag you like
- *what if the library takes a direction I don't like?* Same as for a stale repo
- *what if the owner deletes this repo or makes it private?* The source code for each release is published to maven-central. You can get the source [there](https://repo1.maven.org/maven2/com/c4-soft/springaddons/) or from any of the forks on GitHub (about 50 in August 2023).
- *what is the risk of vulnerabilities introduced by the code in these libs?* This depends on the lib:
  * libs to be used during tests (`spring-addons-oauth2-test` and `spring-addons-starter-oidc-test`) should be imported with `test` scope => it should not be present at runtime => no risk in production
  * `spring-addons-starter-oidc` does some auto-configuration for you: it defines Spring beans involved in your application security. So yes, if a default is miss-configured in this lib, it can have an impact on your app. You should however consider that:
    - an increasing number of user inspect it and open issues or PRs when detecting a problem (the community is probably much bigger than your team working at detecting Spring Security configuration issues in your own projects)
    - having code centralised at one place and reused at many places reduces the risk of a careless mistake in one of your apps
- *what about the upgrade cost?* Each line of spring-addons follows a line of Spring Boot, see [versions and compatibility]({{ site.baseurl }}/compatibility/). The number of migration guides overstates the churn: `8.4.0`, `8.5.0` and `9.2.0` concern `spring-addons-starter-rest` only, and the last breaking change in `spring-addons-starter-oidc` is the `OAuthentication` class in `8.0.0`, which touched applications using that class and none of the properties.

## The risks of writing it yourself

The other half of the decision. A hand-written configuration for a backend consumed by a single-page or mobile application has to get each of the following right, and none of them fails at startup when it is wrong. [What goes wrong without it]({{ site.baseurl }}/what-goes-wrong/) has the symptom, the cause and the fix for each; this is the list by what is at stake.

Security flaws:
- an **open redirect** ([CWE-601](https://cwe.mitre.org/data/definitions/601.html)) as soon as the frontend is allowed to choose where to land after login or logout and the destination is not validated, which is code most BFFs end up writing;
- **CSRF protection disabled** because the session-stored token was unreachable from JavaScript and `csrf.disable()` made the `403`s go away;
- **trusting any issuer** when a multi-tenant resolver builds a JWT decoder from the `iss` claim of the incoming token instead of a list of trusted issuers;
- **tokens in the browser** because the OAuth2 client with a session, the BFF, looked like more work than a public client in JavaScript, which puts the tokens within reach of every script the page runs.

Broken or unexpected behaviours, each reported as a bug in production:
- roles that never become authorities because only the `scope` claim is read;
- preflight requests rejected because CORS was configured on the MVC side rather than on the security chain;
- a login flow which cannot start from a `fetch` because of a cross-origin `302`;
- a login page returned to an API call instead of a `401`;
- random logouts under load, from parallel `refresh_token` flows with rotating refresh tokens ([declined upstream](https://github.com/spring-projects/spring-security/issues/15145));
- a logout which does not end the session at Auth0 or Amazon Cognito, because they do not implement RP-Initiated Logout as specified;
- a user signed out elsewhere in the SSO realm who stays logged in, because Back-Channel Logout is off.

Tests that lie:
- access-control tests which pass with authorities production never grants, because `spring-security-test` builds the `Authentication` itself and never runs the application's converter.

None of the above is impossible to write. All of it is security code which has to be right, which is rewritten identically by every application of this shape, and which silently reverts to the browser-shaped default when a line is lost. The properties exist so that each of these decisions is one line, visible in one file, and covered by the tests of this repository rather than by each application's.
