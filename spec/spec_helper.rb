# frozen_string_literal: true

require 'simplecov'
SimpleCov.start do
  add_filter '/spec/'
  add_filter '/vendor/'
end

ENV['RACK_ENV'] = 'test'
ENV['DATABASE_URL'] = 'postgres://localhost/pgp_auth_test'
ENV['SESSION_SECRET'] = 'test_secret_at_least_64_chars_for_security_abcdefghijklmnopqrstuvwxyz'

require_relative '../config/database'
require_relative '../app'
require 'rspec'
require 'rack/test'
require 'database_cleaner/sequel'
require 'factory_bot'
require 'faker'
require 'webmock/rspec'
require 'timecop'
require 'gpgme'

# Run migrations
Sequel.extension :migration
Sequel::Migrator.run(DB, 'db/migrate')

# Configure RSpec with extracted configuration
require_relative 'support/rspec_configuration'
require_relative 'support/test_helpers'

# Include test helpers
RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.include FactoryBot::Syntax::Methods
  config.include TestHelpers
end

# Disable WebMock by default
WebMock.allow_net_connect!
