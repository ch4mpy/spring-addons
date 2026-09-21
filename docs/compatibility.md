---
title: Versions and compatibility
nav_order: 2
description: "Which spring-addons version to use with which Spring Boot version: 9.x for Boot 4.1, 8.5.x for Boot 3.5, 8.4.x for Boot 3.4, 7.x for Boot 3.3."
---

# Versions and compatibility
{: .no_toc }

Each line of spring-addons targets a line of Spring Boot and is built against it. Fixes land on `master` (Boot 4) first and are ported to the `8.5` and `8.4` branches (Boot 3.5 and 3.4) when they are not specific to Boot 4.

| spring-addons | Spring Boot | Java | Notes |
|---|---|---|---|
| `9.x` | `4.1.x` (`4.0.x` up to `9.1.5`) | 17+ | Current line. `9.4.0` is built against Boot `4.1.1` and Spring Security `7.1.1`, the samples use Spring Cloud `2025.1.3`. |
| `8.5.x` | `3.5.x` | 17+ | Maintenance line on the [`8.5` branch](https://github.com/ch4mpy/spring-addons/tree/8.5): the fixes and improvements of `9.4.x` which are not specific to Boot 4, ported to Boot 3.5. `8.5.0` is built against Boot `3.5.16`, September 2026. |
| `8.4.x` | `3.4.x` | 17+ | Same content as `8.5.x` on the [`8.4` branch](https://github.com/ch4mpy/spring-addons/tree/8.4). `8.4.0` is built against Boot `3.4.13`, September 2026. |
| `8.1.x` | `3.4.x` to `3.5.x` | 17+ | Superseded by `8.4.x` / `8.5.x`. Last release `8.1.25`, March 2026, built against Boot `3.5.11`. |
| `7.x` | `3.3.x` | 17+ | Last release `7.8.12`, November 2024. |

The exact version of the current line is the one in the [Maven Central badge](https://central.sonatype.com/namespace/com.c4-soft.springaddons).

## Release notes and migration guides

Changes are documented per version in the [release notes](https://github.com/ch4mpy/spring-addons/blob/master/release-notes.md). Breaking changes have a guide of their own:

- [Migrating to 9.2.0](https://github.com/ch4mpy/spring-addons/blob/master/migrate-to-9.2.0.md)
- [Migrating from 8.1.x to 8.5.0](https://github.com/ch4mpy/spring-addons/blob/8.5/migrate-to-8.5.0.md) (Boot 3.5) and [to 8.4.0](https://github.com/ch4mpy/spring-addons/blob/8.4/migrate-to-8.4.0.md) (Boot 3.4)
- [Migrating to 8.0.0](https://github.com/ch4mpy/spring-addons/blob/master/migrate-to-8.0.0.md)
- [Migrating to 7.0.0](https://github.com/ch4mpy/spring-addons/blob/master/7.0.0-migration-guide.md)

Every release also has a [GitHub Release](https://github.com/ch4mpy/spring-addons/releases) carrying the same notes, so watching the repository for releases is enough to be told about a new version.
