# frozen_string_literal: true
require_relative "app"
require "rack/csrf"
require "rack/session"

# Proper middleware ordering: sessions first, then CSRF
use Rack::Session::Cookie, 
    secret: ENV.fetch("SESSION_SECRET") { "dev_secret_change_this_to_something_much_longer_at_least_64_chars_for_security" },
    same_site: :strict,
    secure: ENV['RACK_ENV'] == 'production'

use Rack::Csrf, :raise => true, :skip => ['POST:/pgp-auth']

run App.freeze.app
