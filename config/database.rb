# frozen_string_literal: true

require 'sequel'

# Default to local PostgreSQL if no DATABASE_URL is set
database_url = ENV.fetch('DATABASE_URL', 'postgres://localhost/pgp_auth_app')

begin
  DB = Sequel.connect(database_url)
rescue Sequel::DatabaseConnectionError => e
  puts "❌ Database connection failed: #{e.message}"
  puts "Make sure PostgreSQL is installed and running"
  puts "On Arch Linux: sudo systemctl start postgresql"
  puts "Create user: sudo -u postgres createuser -s $USER"
  exit 1
end
