---
title: Versions and compatibility
nav_order: 2
description: "Which spring-addons version to use with which Spring Boot version: 9.x for Boot 4.1, 8.x for Boot 3.4 and 3.5, 7.x for Boot 3.3."
---

# Versions and compatibility
{: .no_toc }

Each major line of spring-addons targets a major line of Spring Boot and is built against it.

| spring-addons | Spring Boot | Java | Notes |
|---|---|---|---|
| `9.x` | `4.1.x` (`4.0.x` up to `9.1.5`) | 17+ | Current line. `9.4.0` is built against Boot `4.1.1` and Spring Security `7.1.1`, the samples use Spring Cloud `2025.1.3`. |
| `8.x` | `3.4.x` to `3.5.x` | 17+ | Last release `8.1.25`, March 2026, built against Boot `3.5.11`. |
| `7.x` | `3.3.x` | 17+ | Last release `7.8.12`, November 2024. |

The exact version of the current line is the one in the [Maven Central badge](https://central.sonatype.com/namespace/com.c4-soft.springaddons).

## Release notes and migration guides

Changes are documented per version in the [release notes](https://github.com/ch4mpy/spring-addons/blob/master/release-notes.md). Breaking changes have a guide of their own:

- [Migrating to 9.2.0](https://github.com/ch4mpy/spring-addons/blob/master/migrate-to-9.2.0.md)
- [Migrating to 8.0.0](https://github.com/ch4mpy/spring-addons/blob/master/migrate-to-8.0.0.md)
- [Migrating to 7.0.0](https://github.com/ch4mpy/spring-addons/blob/master/7.0.0-migration-guide.md)

Every release also has a [GitHub Release](https://github.com/ch4mpy/spring-addons/releases) carrying the same notes, so watching the repository for releases is enough to be told about a new version.
