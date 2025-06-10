# frozen_string_literal: true

require 'roda'
require 'cgi'
require 'tilt/erb'
require_relative 'config/database'
require_relative 'lib/pgp_auth'
require_relative 'lib/rate_limit'
require_relative 'lib/session_manager'
require_relative 'lib/session_middleware'
require 'bcrypt'

# Load helpers
require_relative 'app/helpers/application_helper'

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


  route do |r|

    r.root do
      view 'home'
    end

    # Authentication routes
    r.on 'login' do
      r.get do
        if RateLimit.blocked?(client_ip, 'login')
          RateLimit.time_until_retry(client_ip, 'login')
          @blocked_message = rate_limit_message('login', client_ip)
          view 'login_blocked'
        else
          view 'login'
        end
      end

      r.post do
        if RateLimit.blocked?(client_ip, 'login')
          flash['error'] = rate_limit_message('login', client_ip)
          r.redirect '/login'
        end

        username = r.params['username'].to_s.strip

        if username.empty?
          flash['error'] = 'Username is required'
          r.redirect '/login'
        end

        RateLimit.record_attempt(client_ip, 'login')
        account = DB[:accounts].where(username: username, verified: true).first

        unless account
          flash['error'] = 'Invalid username'
          r.redirect '/login'
        end

        session[:login_username] = username

        if RateLimit.pgp_only_required?(username)
          session[:pgp_only_account_id] = account[:id]
          r.redirect '/login-pgp-only'
        else
          r.redirect '/login-password'
        end
      end
    end

    # Password authentication
    r.on 'login-password' do
      username = session[:login_username]
      r.redirect '/login' unless username

      @username = username

      r.get do
        if RateLimit.blocked?(username, 'password')
          @blocked_message = rate_limit_message('password', username)
          view 'password_blocked'
        else
          view 'login_password'
        end
      end

      r.post do
        if RateLimit.blocked?(username, 'password')
          flash['error'] = rate_limit_message('password', username)
          r.redirect '/login-password'
        end

        handle_password_authentication(r, username)
      end
    end

    # PGP-only authentication
    r.on 'login-pgp-only' do
      account_id = session[:pgp_only_account_id]
      r.redirect '/login' unless account_id

      @account = DB[:accounts].where(id: account_id).first
      r.redirect '/login' unless @account

      r.get do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          @blocked_message = rate_limit_message('2fa', account_id.to_s)
          view 'pgp_blocked'
        else
          generate_pgp_challenge(account_id)
          view 'login_pgp_only'
        end
      end

      r.post do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          flash['error'] = rate_limit_message('2fa', account_id.to_s)
          r.redirect '/login-pgp-only'
        end

        submitted_code = r.params['code'].to_s.strip
        RateLimit.record_attempt(account_id.to_s, '2fa')

        if verify_pgp_challenge(account_id, submitted_code)
          RateLimit.reset_password_failures(@account[:username])
          DB[:challenges].where(account_id: account_id).delete

          create_secure_session(account_id)

          session.delete(:pgp_only_account_id)
          session.delete(:login_username)
          flash['notice'] = 'PGP authentication successful - account security restored'
          r.redirect '/dashboard'
        else
          flash['error'] = 'Incorrect PGP code. Please try again.'
          r.redirect '/login-pgp-only'
        end
      end
    end

    # 2FA authentication
    r.on 'pgp-2fa' do
      account_id = session[:pending_account_id]
      r.redirect '/login' unless account_id

      @account = DB[:accounts].where(id: account_id).first
      r.redirect '/login' unless @account

      r.get do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          @blocked_message = rate_limit_message('2fa', account_id.to_s)
          view 'pgp_blocked'
        else
          generate_pgp_challenge(account_id)
          view 'pgp_2fa'
        end
      end

      r.post do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          flash['error'] = rate_limit_message('2fa', account_id.to_s)
          r.redirect '/pgp-2fa'
        end

        submitted_code = r.params['code'].to_s.strip
        RateLimit.record_attempt(account_id.to_s, '2fa')

        if verify_pgp_challenge(account_id, submitted_code)
          DB[:challenges].where(account_id: account_id).delete

          create_secure_session(account_id)

          session.delete(:pending_account_id)
          flash['notice'] = 'Authentication successful'
          r.redirect '/dashboard'
        else
          flash['error'] = 'Incorrect code. Please try again.'
          r.redirect '/pgp-2fa'
        end
      end
    end

    # Registration routes
    r.on 'register' do
      r.get do
        if RateLimit.blocked?(client_ip, 'register')
          @blocked_message = rate_limit_message('register', client_ip)
          view 'register_blocked'
        else
          view 'register'
        end
      end

      r.post do
        handle_registration(r)
      end
    end

    # PGP verification
    r.on 'verify-pgp' do
      account_id = session[:unverified_account_id]
      unless account_id
        flash['error'] = 'No pending registration found'
        r.redirect '/register'
      end

      @account = DB[:accounts].where(id: account_id).first
      unless @account
        flash['error'] = 'Account not found'
        r.redirect '/register'
      end

      r.get do
        if RateLimit.blocked?(client_ip, 'verify_pgp')
          @blocked_message = rate_limit_message('verify_pgp', client_ip)
          view 'verify_blocked'
        else
          code = PgpAuth.random_code
          DB[:accounts].where(id: account_id).update(
            verification_code: code,
            verification_expires_at: Time.now + 600
          )
          @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)
          view 'verify_pgp'
        end
      end

      r.post do
        if RateLimit.blocked?(client_ip, 'verify_pgp')
          flash['error'] = rate_limit_message('verify_pgp', client_ip)
          r.redirect '/verify-pgp'
        end

        RateLimit.record_attempt(client_ip, 'verify_pgp')
        submitted_code = r.params['code'].to_s.strip

        account = DB[:accounts].where(id: account_id).first

        unless account[:verification_expires_at] &&
               account[:verification_expires_at] > Time.now
          flash['error'] = 'Verification expired. Please try again.'
          r.redirect '/verify-pgp'
        end

        if submitted_code == account[:verification_code]
          complete_verification(r, account_id)
        else
          flash['error'] = 'Incorrect code. Please try again.'
          r.redirect '/verify-pgp'
        end
      end
    end

    # Dashboard routes
    r.on 'dashboard' do
      require_authentication(r) do |account|
        @account = account
        view 'dashboard'
      end
    end

    # Session management
    r.on 'sessions' do
      require_authentication(r) do |account|
        @account = account

        r.get do
          @sessions = SessionManager.get_active_sessions(account[:id])
          @current_token = session[:session_token]
          view 'sessions'
        end

        r.post 'revoke' do
          token = r.params['token']
          if token && token != session[:session_token]
            SessionManager.revoke_session(token, 'user_revoked')
            flash['notice'] = 'Session revoked successfully'
          end
          r.redirect '/sessions'
        end

        r.post 'revoke_all' do
          count = SessionManager.revoke_all_sessions(
            account[:id],
            session[:session_token]
          )
          flash['notice'] = "#{count} sessions revoked"
          r.redirect '/sessions'
        end
      end
    end

    # Security dashboard
    r.on 'security' do
      require_authentication(r) do |account|
        @account = account
        @audit_log = SessionManager.get_audit_log(account[:id])
        @active_sessions = SessionManager.get_active_sessions(account[:id])
        @rate_limit_status = {
          login: RateLimit.time_until_retry(client_ip, 'login'),
          password: RateLimit.time_until_retry(account[:username], 'password'),
          twofa: RateLimit.time_until_retry(account[:id].to_s, '2fa')
        }
        view 'security'
      end
    end

    # Logout
    r.on 'logout' do
      r.get { view 'logout' }

      r.post do
        clear_session_and_logout
        flash['notice'] = 'You have been logged out'
        r.redirect '/'
      end
    end
  end

  private

  def handle_password_authentication(r, username)
    password = r.params['password'].to_s

    if password.empty?
      flash['error'] = 'Password is required'
      r.redirect '/login-password'
    end

    account = DB[:accounts].where(username: username, verified: true).first

    if account && BCrypt::Password.new(account[:password_hash]) == password
      session[:pending_account_id] = account[:id]
      session.delete(:login_username)
      r.redirect '/pgp-2fa'
    else
      pgp_only_triggered = RateLimit.record_password_failure(username)

      if pgp_only_triggered
        flash['notice'] = 'Too many password failures. ' \
                          'This account now requires PGP-only authentication.'
        session[:pgp_only_account_id] = account[:id] if account
        session.delete(:login_username)
        r.redirect '/login-pgp-only'
      else
        flash['error'] = 'Invalid password'
        r.redirect '/login-password'
      end
    end
  end

  def handle_registration(r)
    if RateLimit.blocked?(client_ip, 'register')
      flash['error'] = rate_limit_message('register', client_ip)
      r.redirect '/register'
    end

    RateLimit.record_attempt(client_ip, 'register')

    params = validate_registration_params(r)
    return unless params

    begin
      fp = PgpAuth.import_and_fingerprint(params[:key_text])

      if DB[:accounts].where(fingerprint: fp).count.positive?
        flash['error'] = 'This PGP key is already registered'
        r.redirect '/register'
      end

      create_unverified_account(r, params, fp)
    rescue StandardError => e
      flash['error'] = "Invalid PGP key: #{e.message}"
      r.redirect '/register'
    end
  end

  def validate_registration_params(r)
    username = r.params['username'].to_s.strip
    password = r.params['password'].to_s
    key_text = r.params['public_key'].to_s.strip

    if username.empty? || password.empty? || key_text.empty?
      flash['error'] = 'All fields are required'
      r.redirect '/register'
      return nil
    end

    if username.length < 3 || username.length > 50
      flash['error'] = 'Username must be between 3 and 50 characters'
      r.redirect '/register'
      return nil
    end

    if password.length < 8
      flash['error'] = 'Password must be at least 8 characters long'
      r.redirect '/register'
      return nil
    end

    if DB[:accounts].where(username: username).count.positive?
      flash['error'] = 'Username already taken'
      r.redirect '/register'
      return nil
    end

    { username: username, password: password, key_text: key_text }
  end

  def create_unverified_account(r, params, fingerprint)
    password_hash = BCrypt::Password.create(params[:password])

    id = DB[:accounts].insert(
      username: params[:username],
      password_hash: password_hash,
      public_key: params[:key_text],
      fingerprint: fingerprint,
      verified: false,
      pgp_only_mode: false,
      failed_password_count: 0
    )

    session[:unverified_account_id] = id
    r.redirect '/verify-pgp'
  end

  def complete_verification(r, account_id)
    DB[:accounts].where(id: account_id).update(
      verified: true,
      verification_code: nil,
      verification_expires_at: nil
    )

    create_secure_session(account_id)

    session.delete(:unverified_account_id)
    flash['notice'] = 'Account created and verified successfully!'
    r.redirect '/dashboard'
  end

  def generate_pgp_challenge(account_id)
    DB[:challenges].where(account_id: account_id)
                   .where { expires_at < Time.now }
                   .delete

    code = PgpAuth.random_code
    DB[:challenges].insert(
      account_id: account_id,
      code: code,
      expires_at: Time.now + 300
    )
    @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)
  end

  def verify_pgp_challenge(account_id, submitted_code)
    row = DB[:challenges].where(account_id: account_id)
                         .reverse(:id).first

    row && row[:expires_at] > Time.now && submitted_code == row[:code]
  end

  def require_authentication(r)
    r.redirect '/login' unless session[:auth_account_id]

    account_id = session[:auth_account_id]
    account = DB[:accounts].where(id: account_id).first

    unless account
      clear_session_and_logout
      r.redirect '/login'
    end

    yield account
  end
end
