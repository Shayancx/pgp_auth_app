require "sequel"
DB = Sequel.connect(ENV.fetch("DATABASE_URL") { "postgres://localhost/pgp_auth_app" })
