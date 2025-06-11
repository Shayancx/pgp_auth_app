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

# SECURITY HARDENED: Ensure required environment variables
unless ENV['SESSION_SECRET']
  puts '❌ SESSION_SECRET environment variable is required!'
  puts 'Generate one with: openssl rand -hex 64'
  exit 1
end

# SECURITY HARDENED: Enhanced session middleware
use Rack::Session::Cookie,
    secret: ENV.fetch('SESSION_SECRET'),
    same_site: :strict,  # Stricter
    secure: ENV['RACK_ENV'] == 'production',
    httponly: true,
    key: 'pgp_auth_session',
    expire_after: 3600,  # Reduced to 1 hour
    path: '/',
    domain: ENV['SESSION_DOMAIN']

# SECURITY HARDENED: Strict CSRF Protection
require 'rack/csrf'
use Rack::Csrf,
    raise: true,  # Fail hard on CSRF violations
    field: 'authenticity_token',
    header: 'X-CSRF-Token',
    check_also: :referrer

# SECURITY HARDENED: Comprehensive security headers
use(Class.new do
  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, body = @app.call(env)
    
    # SECURITY HARDENED: Military-grade security headers
    headers.merge!({
      'X-Frame-Options' => 'DENY',
      'X-Content-Type-Options' => 'nosniff',
      'X-XSS-Protection' => '0',  # Disable deprecated header
      'Referrer-Policy' => 'no-referrer',
      'Permissions-Policy' => 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()',
      'Content-Security-Policy' => "default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'none'; object-src 'none'; child-src 'none'; frame-src 'none'; worker-src 'none'; form-action 'self'; base-uri 'self'; manifest-src 'none'",
      'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains; preload',
      'Cache-Control' => 'no-cache, no-store, must-revalidate, private',
      'Pragma' => 'no-cache',
      'Expires' => '0',
      'X-Permitted-Cross-Domain-Policies' => 'none',
      'Cross-Origin-Embedder-Policy' => 'require-corp',
      'Cross-Origin-Opener-Policy' => 'same-origin',
      'Cross-Origin-Resource-Policy' => 'same-origin'
    })
    
    [status, headers, body]
  end
end)

# SECURITY HARDENED: Request size limits
use Rack::ContentLength
use(Class.new do
  def initialize(app)
    @app = app
  end

  def call(env)
    # Limit request size
    if env['CONTENT_LENGTH'] && env['CONTENT_LENGTH'].to_i > 1_000_000  # 1MB limit
      return [413, {}, ['Request too large']]
    end
    
    @app.call(env)
  end
end)

run App.freeze.app
