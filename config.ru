# frozen_string_literal: true

require_relative 'app'
require 'rack/session'

# Session middleware
use Rack::Session::Cookie,
    secret: ENV.fetch('SESSION_SECRET'),
    same_site: :lax,
    secure: ENV['RACK_ENV'] == 'production',
    httponly: true,
    key: 'pgp_auth_session'

# TODO: Re-enable CSRF protection once gem issues are resolved
# require 'rack_csrf'
# use Rack::Csrf, raise: true

run App.freeze.app
