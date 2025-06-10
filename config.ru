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

# Validate session secret strength
if ENV['SESSION_SECRET'].length < 64
  puts '❌ SESSION_SECRET must be at least 64 characters!'
  exit 1
end

# Enhanced session middleware with security settings
use Rack::Session::Cookie,
    secret: ENV.fetch('SESSION_SECRET'),
    same_site: ENV['RACK_ENV'] == 'production' ? :strict : :lax,
    secure: ENV['RACK_ENV'] == 'production',
    httponly: true,
    key: 'pgp_auth_session',
    expire_after: ENV.fetch('SESSION_TIMEOUT', '86400').to_i,
    path: '/',
    defer: true

# CSRF Protection with lenient development settings
require 'rack/csrf'
use Rack::Csrf,
    raise: false,  # Don't raise in development, just return 403
    skip_if: lambda { |req| 
      # Skip CSRF for GET, HEAD, OPTIONS requests
      %w[GET HEAD OPTIONS].include?(req.request_method) ||
      req.path == '/health' ||
      req.path.start_with?('/public') ||
      req.path.start_with?('/assets')
    },
    key: 'csrf.token',
    header: 'X-CSRF-Token',
    field: 'authenticity_token'  # Standard Rails field name

# Rack::Protection middleware (without Base class)
require 'rack/protection'
use Rack::Protection::EscapedParams
use Rack::Protection::FormToken
use Rack::Protection::FrameOptions
use Rack::Protection::PathTraversal
use Rack::Protection::XSSHeader

# Custom security headers middleware
use(Class.new do
  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, body = @app.call(env)
    
    # Enhanced security headers
    headers.merge!({
      'X-Frame-Options' => 'DENY',
      'X-Content-Type-Options' => 'nosniff',
      'X-XSS-Protection' => '1; mode=block',
      'Referrer-Policy' => 'strict-origin-when-cross-origin',
      'Permissions-Policy' => 'geolocation=(), microphone=(), camera=(), payment=()',
      'Content-Security-Policy' => [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "object-src 'none'"
      ].join('; '),
      'Strict-Transport-Security' => ENV['RACK_ENV'] == 'production' ? 'max-age=31536000; includeSubDomains' : nil,
      'Cache-Control' => 'no-cache, no-store, must-revalidate, private',
      'Pragma' => 'no-cache',
      'Expires' => '0'
    }.compact)
    
    [status, headers, body]
  end
end)

run App.freeze.app
