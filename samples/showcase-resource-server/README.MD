# Resource-server sample

By activating **jwt** profile, you can switch from opaque bearer tokens introspection to JWT.

By activating **jpa** profile, you can switch authorities lookup from `authorities` token claim to H2 database table (see `resources/data.sql` for fixtures).
