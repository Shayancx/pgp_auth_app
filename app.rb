# frozen_string_literal: true

require 'roda'
require 'cgi'
require 'tilt/erb'
require_relative 'config/database'
require 'rodauth'
require_relative 'lib/pgp_auth'
require_relative 'lib/rate_limit'
require_relative 'pgp_challenge_feature'
require_relative 'lib/session_manager'
require_relative 'lib/session_middleware'
require 'bcrypt'

# Load helpers and routes
require_relative 'app/helpers/application_helper'
require_relative 'app/routes/authentication'
require_relative 'app/routes/pgp_authentication'
require_relative 'app/routes/registration'
require_relative 'app/routes/dashboard'

# Main Roda application for PGP-based authentication
class App < Roda
  include ApplicationHelper

  plugin :flash
  plugin :render, engine: 'erb', views: 'views'
  plugin :public
  plugin :default_headers, { 'Content-Type' => 'text/html; charset=UTF-8' }

  # Session security middleware
  plugin :middleware do |middleware|
    middleware.use SessionMiddleware
  end

  plugin :rodauth do
    enable :base, :pgp_challenge
  end

  # Register route modules
  plugin Routes::Authentication
  plugin Routes::PgpAuthentication
  plugin Routes::Registration
  plugin Routes::Dashboard

  route do |r|
    r.rodauth

    r.root do
      view 'home'
    end
  end
end
