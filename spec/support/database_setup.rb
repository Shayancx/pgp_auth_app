# frozen_string_literal: true

# Ensure test database exists
require 'pg'

begin
  conn = PG.connect(dbname: 'postgres', host: 'localhost')
  conn.exec('CREATE DATABASE pgp_auth_test')
rescue PG::DuplicateDatabase
  # Database already exists
ensure
  conn&.close
end
