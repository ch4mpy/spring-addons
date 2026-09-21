---
title: Articles
nav_order: 9
has_children: true
description: "Longer-form write-ups on the two problems spring-addons solves that nothing else does: a complete OAuth2 BFF for a single-page application, and refresh token flow de-duplication."
---

# Articles

Reference pages answer "how do I configure this". These answer "why is this hard in the first place", and they are readable without taking the dependency. The short version of both, together with everything else the defaults get wrong for a JavaScript or mobile caller, is [what goes wrong without it]({{ site.baseurl }}/what-goes-wrong/).

- [An OAuth2 BFF for a single-page application, end to end]({{ site.baseurl }}/articles/bff/): what the pattern actually requires once you leave the diagram, and the six Spring Security behaviours a browser-based frontend needs which the defaults do not provide.
- [One refresh token flow at a time]({{ site.baseurl }}/articles/refresh-token-stampede/): why rotating refresh tokens produce random `401`s under parallel requests, why Spring Security declined to solve it, and what a correct de-duplication has to get right.

Three tutorials from this repository are published on Baeldung: [Getting started with Keycloak and Spring Boot](https://www.baeldung.com/spring-boot-keycloak), [Creating an OAuth2 BFF with `spring-cloud-gateway`](https://www.baeldung.com/spring-cloud-gateway-bff-oauth2), and [Testing access control with mocked OAuth2 authentications](https://www.baeldung.com/spring-oauth-testing-access-control).
