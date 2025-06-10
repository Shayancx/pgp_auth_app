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

class App < Roda
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

  # Helper to get client IP
  def client_ip
    env['HTTP_X_FORWARDED_FOR']&.split(',')&.first&.strip ||
      env['HTTP_X_REAL_IP'] ||
      env['REMOTE_ADDR'] ||
      'unknown'
  end

  route do |r|
    r.rodauth

    r.root do
      view 'home'
    end

    # Handle logout manually
    r.on 'logout' do
      r.get do
        view 'logout'
      end

      r.post do
        # Revoke session properly
        SessionManager.revoke_session(session[:session_token], 'user_logout') if session[:session_token]
        session.clear
        flash['notice'] = 'You have been logged out'
        r.redirect '/'
      end
    end

    # Step 1: Username-only login
    r.on 'login' do
      r.get do
        # Check if IP is blocked for login attempts
        if RateLimit.blocked?(client_ip, 'login')
          time_remaining = RateLimit.time_until_retry(client_ip, 'login')
          @blocked_message = "Too many login attempts from your IP. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          view 'login_blocked'
        else
          view 'login'
        end
      end

      r.post do
        # Block if IP is rate limited
        if RateLimit.blocked?(client_ip, 'login')
          time_remaining = RateLimit.time_until_retry(client_ip, 'login')
          flash['error'] =
            "Too many login attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          r.redirect '/login'
        end

        username = r.params['username'].to_s.strip

        if username.empty?
          flash['error'] = 'Username is required'
          r.redirect '/login'
        end

        # Record login attempt
        RateLimit.record_attempt(client_ip, 'login')

        # Check if user exists and is verified
        account = DB[:accounts].where(username: username, verified: true).first

        unless account
          flash['error'] = 'Invalid username'
          r.redirect '/login'
        end

        # Store username for next step
        session[:login_username] = username

        # Check if account requires PGP-only authentication
        if RateLimit.pgp_only_required?(username)
          # Skip password, go directly to PGP
          session[:pgp_only_account_id] = account[:id]
          r.redirect '/login-pgp-only'
        else
          # Normal flow: proceed to password
          r.redirect '/login-password'
        end
      end
    end

    # Step 2a: Password entry (normal flow)
    r.on 'login-password' do
      username = session[:login_username]
      r.redirect '/login' unless username

      @username = username

      r.get do
        # Check if username is blocked for password attempts
        if RateLimit.blocked?(username, 'password')
          time_remaining = RateLimit.time_until_retry(username, 'password')
          @blocked_message = "Too many password attempts for this account. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          view 'password_blocked'
        else
          view 'login_password'
        end
      end

      r.post do
        # Block if username is rate limited for passwords
        if RateLimit.blocked?(username, 'password')
          time_remaining = RateLimit.time_until_retry(username, 'password')
          flash['error'] =
            "Too many password attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          r.redirect '/login-password'
        end

        password = r.params['password'].to_s

        if password.empty?
          flash['error'] = 'Password is required'
          r.redirect '/login-password'
        end

        account = DB[:accounts].where(username: username, verified: true).first

        if account && BCrypt::Password.new(account[:password_hash]) == password
          # Password correct, proceed to 2FA
          session[:pending_account_id] = account[:id]
          session.delete(:login_username)
          r.redirect '/pgp-2fa'
        else
          # Record password failure
          pgp_only_triggered = RateLimit.record_password_failure(username)

          if pgp_only_triggered
            # Account now requires PGP-only authentication
            flash['notice'] = 'Too many password failures. This account now requires PGP-only authentication.'
            session[:pgp_only_account_id] = account[:id] if account
            session.delete(:login_username)
            r.redirect '/login-pgp-only'
          else
            flash['error'] = 'Invalid password'
            r.redirect '/login-password'
          end
        end
      end
    end

    # Step 2b: PGP-only authentication (security escalation)
    r.on 'login-pgp-only' do
      account_id = session[:pgp_only_account_id]
      r.redirect '/login' unless account_id

      @account = DB[:accounts].where(id: account_id).first
      r.redirect '/login' unless @account

      r.get do
        # Check if account is blocked for 2FA attempts
        if RateLimit.blocked?(account_id.to_s, '2fa')
          time_remaining = RateLimit.time_until_retry(account_id.to_s, '2fa')
          @blocked_message = "Too many PGP attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          view 'pgp_blocked'
        else
          # Clean up expired challenges
          DB[:challenges].where(account_id: account_id)
                         .where { expires_at < Time.now }
                         .delete

          code = PgpAuth.random_code
          DB[:challenges].insert(account_id: account_id,
                                 code: code,
                                 expires_at: Time.now + 300)
          @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)

          view 'login_pgp_only'
        end
      end

      r.post do
        # Block if account is rate limited
        if RateLimit.blocked?(account_id.to_s, '2fa')
          time_remaining = RateLimit.time_until_retry(account_id.to_s, '2fa')
          flash['error'] =
            "Too many PGP attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          r.redirect '/login-pgp-only'
        end

        submitted_code = r.params['code'].to_s.strip

        # Record 2FA attempt
        RateLimit.record_attempt(account_id.to_s, '2fa')

        row = DB[:challenges].where(account_id: account_id)
                             .reverse(:id).first

        unless row && row[:expires_at] > Time.now
          flash['error'] = 'Challenge expired. Please try again.'
          r.redirect '/login-pgp-only'
        end

        if submitted_code == row[:code]
          # Successful PGP authentication - reset password failures
          RateLimit.reset_password_failures(@account[:username])

          DB[:challenges].where(account_id: account_id).delete
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          session[:rodauth_session_key] = account_id
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

    # Registration flow
    r.on 'register' do
      r.get do
        if RateLimit.blocked?(client_ip, 'register')
          time_remaining = RateLimit.time_until_retry(client_ip, 'register')
          @blocked_message = "Too many registration attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          view 'register_blocked'
        else
          view 'register'
        end
      end

      r.post do
        # Block if IP is rate limited
        if RateLimit.blocked?(client_ip, 'register')
          time_remaining = RateLimit.time_until_retry(client_ip, 'register')
          flash['error'] =
            "Too many registration attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          r.redirect '/register'
        end

        # Record registration attempt
        RateLimit.record_attempt(client_ip, 'register')

        username = r.params['username'].to_s.strip
        password = r.params['password'].to_s
        key_text = r.params['public_key'].to_s.strip

        if username.empty? || password.empty? || key_text.empty?
          flash['error'] = 'All fields are required'
          r.redirect '/register'
        end

        if username.length < 3 || username.length > 50
          flash['error'] = 'Username must be between 3 and 50 characters'
          r.redirect '/register'
        end

        if password.length < 8
          flash['error'] = 'Password must be at least 8 characters long'
          r.redirect '/register'
        end

        # Check if username already exists
        if DB[:accounts].where(username: username).count.positive?
          flash['error'] = 'Username already taken'
          r.redirect '/register'
        end

        begin
          fp = PgpAuth.import_and_fingerprint(key_text)

          # Check if this fingerprint is already used
          if DB[:accounts].where(fingerprint: fp).count.positive?
            flash['error'] = 'This PGP key is already registered'
            r.redirect '/register'
          end

          password_hash = BCrypt::Password.create(password)

          # Create unverified account
          id = DB[:accounts].insert(
            username: username,
            password_hash: password_hash,
            public_key: key_text,
            fingerprint: fp,
            verified: false,
            pgp_only_mode: false,
            failed_password_count: 0
          )

          session[:unverified_account_id] = id
          r.redirect '/verify-pgp'
        rescue StandardError => e
          flash['error'] = "Invalid PGP key: #{e.message}"
          r.redirect '/register'
        end
      end
    end

    # PGP verification for new accounts
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
          time_remaining = RateLimit.time_until_retry(client_ip, 'verify_pgp')
          @blocked_message = "Too many verification attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          view 'verify_blocked'
        else
          # Generate verification challenge
          code = PgpAuth.random_code
          DB[:accounts].where(id: account_id).update(
            verification_code: code,
            verification_expires_at: Time.now + 600 # 10 minutes
          )
          @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)

          view 'verify_pgp'
        end
      end

      r.post do
        # Block if IP is rate limited
        if RateLimit.blocked?(client_ip, 'verify_pgp')
          time_remaining = RateLimit.time_until_retry(client_ip, 'verify_pgp')
          flash['error'] =
            "Too many verification attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          r.redirect '/verify-pgp'
        end

        # Record verification attempt
        RateLimit.record_attempt(client_ip, 'verify_pgp')

        submitted_code = r.params['code'].to_s.strip

        # Reload account to get latest verification code
        account = DB[:accounts].where(id: account_id).first

        unless account[:verification_expires_at] && account[:verification_expires_at] > Time.now
          flash['error'] = 'Verification expired. Please try again.'
          r.redirect '/verify-pgp'
        end

        if submitted_code == account[:verification_code]
          # Mark account as verified
          DB[:accounts].where(id: account_id).update(
            verified: true,
            verification_code: nil,
            verification_expires_at: nil
          )

          # Log the user in
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          session[:rodauth_session_key] = account_id
          session.delete(:unverified_account_id)
          flash['notice'] = 'Account created and verified successfully!'
          r.redirect '/dashboard'
        else
          flash['error'] = 'Incorrect code. Please try again.'
          r.redirect '/verify-pgp'
        end
      end
    end

    # Normal 2FA flow (after password authentication)
    r.on 'pgp-2fa' do
      account_id = session[:pending_account_id]
      r.redirect '/login' unless account_id

      @account = DB[:accounts].where(id: account_id).first
      r.redirect '/login' unless @account

      r.get do
        if RateLimit.blocked?(account_id.to_s, '2fa')
          time_remaining = RateLimit.time_until_retry(account_id.to_s, '2fa')
          @blocked_message = "Too many 2FA attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          view 'pgp_blocked'
        else
          # Clean up expired challenges
          DB[:challenges].where(account_id: account_id)
                         .where { expires_at < Time.now }
                         .delete

          code = PgpAuth.random_code
          DB[:challenges].insert(account_id: account_id,
                                 code: code,
                                 expires_at: Time.now + 300)
          @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)

          view 'pgp_2fa'
        end
      end

      r.post do
        # Block if account is rate limited
        if RateLimit.blocked?(account_id.to_s, '2fa')
          time_remaining = RateLimit.time_until_retry(account_id.to_s, '2fa')
          flash['error'] =
            "Too many 2FA attempts. Please try again in #{RateLimit.format_time_remaining(time_remaining)}"
          r.redirect '/pgp-2fa'
        end

        submitted_code = r.params['code'].to_s.strip

        # Record 2FA attempt
        RateLimit.record_attempt(account_id.to_s, '2fa')

        row = DB[:challenges].where(account_id: account_id)
                             .reverse(:id).first

        unless row && row[:expires_at] > Time.now
          flash['error'] = 'Challenge expired. Please try again.'
          r.redirect '/pgp-2fa'
        end

        if submitted_code == row[:code]
          DB[:challenges].where(account_id: account_id).delete
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          # Create secure session
          session_token = SessionManager.create_session(account_id, client_ip, env['HTTP_USER_AGENT'])
          session[:session_token] = session_token
          session[:rodauth_session_key] = account_id
          session.delete(:pending_account_id)
          flash['notice'] = 'Authentication successful'
          r.redirect '/dashboard'
        else
          flash['error'] = 'Incorrect code. Please try again.'
          r.redirect '/pgp-2fa'
        end
      end
    end

    # Session Management
    r.on 'sessions' do
      r.redirect '/login' unless session[:rodauth_session_key]

      account_id = session[:rodauth_session_key]
      @account = DB[:accounts].where(id: account_id).first

      unless @account
        session.clear
        r.redirect '/login'
      end

      r.get do
        @sessions = SessionManager.get_active_sessions(account_id)
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
        count = SessionManager.revoke_all_sessions(account_id, session[:session_token])
        flash['notice'] = "#{count} sessions revoked"
        r.redirect '/sessions'
      end
    end

    # Security Dashboard
    r.on 'security' do
      r.redirect '/login' unless session[:rodauth_session_key]

      account_id = session[:rodauth_session_key]
      @account = DB[:accounts].where(id: account_id).first

      unless @account
        session.clear
        r.redirect '/login'
      end

      @audit_log = SessionManager.get_audit_log(account_id)
      @active_sessions = SessionManager.get_active_sessions(account_id)
      @rate_limit_status = {
        login: RateLimit.time_until_retry(client_ip, 'login'),
        password: RateLimit.time_until_retry(@account[:username], 'password'),
        twofa: RateLimit.time_until_retry(account_id.to_s, '2fa')
      }

      view 'security'
    end
    # Dashboard
    r.on 'dashboard' do
      r.redirect '/login' unless session[:rodauth_session_key]

      account_id = session[:rodauth_session_key]
      @account = DB[:accounts].where(id: account_id).first

      unless @account
        # Revoke session properly
        SessionManager.revoke_session(session[:session_token], 'user_logout') if session[:session_token]
        session.clear
        r.redirect '/login'
      end

      view 'dashboard'
    end
  end

  def csrf_tag
    Rack::Csrf.csrf_tag(env)
  end
end
