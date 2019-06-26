# Resource-server sample
By activating **jwt** profile, you can switch from opaque bearer tokens introspection to JWT.

By activating **authorities-claim** profile, you can switch authorities lookup from H2 database table (see `resources/data.sql` for fixtures) to `authorities` token claim.
