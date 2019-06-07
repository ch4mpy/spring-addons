# Samples
Authorization and resource servers designed to work together.

## Choosing token format
By default, it exchange opaque Bearer tokens and use introspection end-point.

You can switch to JWT by activating **jwt** profile on **both** applications.

## Choosing authorities lookup mode
By default, the resource-server expects authorities to be provided by authorization server in **authorities** claim
(either inside the JWT or from introspection end-point).

By activating the **jpa** profile, you can switch to a database lookup: resource server retrieves authorities by "subject" from a H2 database.
Initialization script is the regular one for spring-boot: data.sql in resources folder.