# frozen_string_literal: true

require_relative 'session_manager'

class SessionMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    request = Rack::Request.new(env)

    # Skip middleware for non-authenticated routes
    path = request.path
    skip_paths = ['/', '/login', '/register', '/verify-pgp']

    unless skip_paths.include?(path) || path.start_with?('/public')
      session_token = request.session[:session_token]

      if session_token
        account_id = SessionManager.validate_session(
          session_token,
          get_client_ip(env),
          env['HTTP_USER_AGENT']
        )

        if account_id
          # Session is valid, store account_id for use in app
          env['authenticated_account_id'] = account_id
        else
          # Session invalid, clear it
          request.session.clear
          env['session_expired'] = true
        end
      end
    end

    @app.call(env)
  end

  private

  def get_client_ip(env)
    env['HTTP_X_FORWARDED_FOR']&.split(',')&.first&.strip ||
      env['HTTP_X_REAL_IP'] ||
      env['REMOTE_ADDR'] ||
      'unknown'
  end
end
