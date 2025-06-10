# frozen_string_literal: true

require_relative 'app'
require 'rack/session'

# Session middleware only for now
use Rack::Session::Cookie,
    secret: ENV.fetch('SESSION_SECRET',
                      'dev_secret_change_this_to_something_much_longer_at_least_64_chars_for_security'),
    same_site: :lax,
    secure: ENV['RACK_ENV'] == 'production',
    httponly: true,
    key: 'pgp_auth_session'

# TODO: Re-enable CSRF protection once core functionality is working
# use Rack::Csrf, raise: true

run App.freeze.app
