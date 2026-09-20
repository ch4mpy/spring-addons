---
title: Risks and mitigations
parent: spring-addons-starter-oidc
nav_order: 5
description: "What can go wrong when depending on a third-party Spring Security starter, and how to protect against each case. Every auto-configured bean is @ConditionalOnMissingBean, so opting out is incremental."
---

# Risks of using these libs, and mitigations

Neither the owner of this repo nor any of the contributors are part of Spring Security team. At best, some are occasional contributors to the "official" framework.

However, unless you have a deep knowledge of Spring Security for OAuth2, using `spring-addons-starter-oidc` might actually be safer than experimenting with the conf by yourself. And the more popularity this repo gets, the safer it is: more people detect potential issues, more people can keep it alive if its initiator disappears and, if some features where to become popular enough, Spring team could consider pulling it in the official framework.

Also, all you have to do to opt-out `spring-addons-starter-oidc` at any point in time is writing Spring Security configuration by yourself: each of the beans listed in the features below is `@ConditionalOnMissingBean`, so you can take back one of them at a time, and eventually the whole `Security(Web)FilterChain`, with just `spring-boot-starter-oauth2-client` or `spring-boot-starter-oauth2-resource-server`.

What are the identified risks of using the resources from such a repo and how can you protect against it?
- *what if the updates to latest dependencies stop and no PR are merged anymore?* You can fork this repo and start a new branch from the last tag you like
- *what if the library takes a direction I don't like?* Same as for a stale repo
- *what if the owner deletes this repo or makes it private?* The source code for each release is published to maven-central. You can get the source [there](https://repo1.maven.org/maven2/com/c4-soft/springaddons/) or from any of the forks on GitHub (about 50 in August 2023).
- *what is the risk of vulnerabilities introduced by the code in these libs?* This depends on the lib:
  * libs to be used during tests (`spring-addons-oauth2-test` and `spring-addons-starter-oidc-test`) should be imported with `test` scope => it should not be present at runtime => no risk in production
  * `spring-addons-starter-oidc` does some auto-configuration for you: it defines Spring beans involved in your application security. So yes, if a default is miss-configured in this lib, it can have an impact on your app. You should however consider that:
    - an increasing number of user inspect it and open issues or PRs when detecting a problem (the community is probably much bigger than your team working at detecting Spring Security configuration issues in your own projects)
    - having code centralised at one place and reused at many places reduces the risk of a careless mistake in one of your apps

