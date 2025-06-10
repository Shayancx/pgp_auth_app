# frozen_string_literal: true

require_relative 'app'
require 'rack/session'
require 'securerandom'

# Ensure SESSION_SECRET is set
unless ENV['SESSION_SECRET']
  puts '❌ SESSION_SECRET environment variable is required!'
  puts 'Generate one with: openssl rand -hex 64'
  exit 1
end

# Session middleware with secure settings
use Rack::Session::Cookie,
    secret: ENV.fetch('SESSION_SECRET'),
    same_site: :lax,
    secure: ENV['RACK_ENV'] == 'production',
    httponly: true,
    key: 'pgp_auth_session',
    expire_after: 86_400 # 24 hours

# CSRF Protection
require 'rack/csrf'
use Rack::Csrf,
    raise: true,
    skip: ['GET:/'],
    check_only: ['POST:*']

run App.freeze.app
