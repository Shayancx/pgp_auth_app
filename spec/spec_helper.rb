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

# Configure RSpec
RSpec.configure do |config|
  config.include Rack::Test::Methods
  config.include FactoryBot::Syntax::Methods

  def app
    App
  end

  # Database Cleaner configuration
  config.before(:suite) do
    DatabaseCleaner[:sequel].strategy = :transaction
    DatabaseCleaner[:sequel].clean_with(:truncation)
    FactoryBot.find_definitions
  end

  config.around(:each) do |example|
    DatabaseCleaner[:sequel].cleaning do
      example.run
    end
  end

  config.after(:each) do
    Timecop.return
  end

  # Helper methods
  def generate_pgp_keypair
    GPGME::Key.create(
      name: 'Test User',
      email: 'test@example.com',
      expires_in: '1y'
    )
  end

  def import_test_key
    key_text = File.read('spec/fixtures/test_public_key.asc')
    GPGME::Key.import(key_text)
    key_text
  end

  def decrypt_challenge(encrypted_text)
    crypto = GPGME::Crypto.new
    crypto.decrypt(encrypted_text).to_s.strip
  end

  def login_as(account)
    post '/login', username: account[:username]
    post '/login-password', password: 'password123'
    
    # Get and solve PGP challenge
    get '/pgp-2fa'
    encrypted = last_response.body.match(/<pre class="encrypted-text">(.*?)<\/pre>/m)[1]
    code = decrypt_challenge(CGI.unescapeHTML(encrypted))
    post '/pgp-2fa', code: code
  end
end

# Disable WebMock by default
WebMock.allow_net_connect!
