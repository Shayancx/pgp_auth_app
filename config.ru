# frozen_string_literal: true

require_relative 'app'
require 'rack/session'

# Load environment variables
if File.exist?('.env')
  File.readlines('.env').each do |line|
    next if line.strip.empty? || line.start_with?('#')
    key, value = line.strip.split('=', 2)
    ENV[key] = value if key && value
  end
end

# Ensure SESSION_SECRET is set
unless ENV['SESSION_SECRET']
  puts '❌ SESSION_SECRET environment variable is required!'
  puts 'Generate one with: openssl rand -hex 64'
  exit 1
end

# Session middleware - MUST come first
use Rack::Session::Cookie,
    secret: ENV.fetch('SESSION_SECRET'),
    same_site: :lax,
    secure: false,  # Allow HTTP in development
    httponly: true,
    key: 'pgp_auth_session',
    expire_after: 86400,
    path: '/'

# Simplified CSRF Protection - no complex options
require 'rack/csrf'
use Rack::Csrf,
    raise: false,
    field: 'authenticity_token'

# Security headers
use(Class.new do
  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, body = @app.call(env)
    
    headers.merge!({
      'X-Frame-Options' => 'DENY',
      'X-Content-Type-Options' => 'nosniff',
      'Cache-Control' => 'no-cache, no-store, must-revalidate'
    })
    
    [status, headers, body]
  end
end)

run App.freeze.app
