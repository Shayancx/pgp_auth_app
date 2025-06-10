# frozen_string_literal: true

# Routes for user registration and verification
module Routes
  # Registration and PGP key verification routes
  module Registration
    def self.registered(app)
      app.instance_eval do
        # Registration flow
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
            handle_verification_get(account_id)
          end

          r.post do
            handle_verification_post(r, account_id)
          end
        end
      end
    end

    def self.handle_registration(r)
      if RateLimit.blocked?(client_ip, 'register')
        r.flash['error'] = rate_limit_message('register', client_ip)
        r.redirect '/register'
      end

      RateLimit.record_attempt(client_ip, 'register')

      params = validate_registration_params(r)
      return unless params

      begin
        fp = PgpAuth.import_and_fingerprint(params[:key_text])

        if DB[:accounts].where(fingerprint: fp).count.positive?
          r.flash['error'] = 'This PGP key is already registered'
          r.redirect '/register'
        end

        create_unverified_account(r, params, fp)
      rescue StandardError => e
        r.flash['error'] = "Invalid PGP key: #{e.message}"
        r.redirect '/register'
      end
    end

    def self.validate_registration_params(r)
      username = r.params['username'].to_s.strip
      password = r.params['password'].to_s
      key_text = r.params['public_key'].to_s.strip

      if username.empty? || password.empty? || key_text.empty?
        r.flash['error'] = 'All fields are required'
        r.redirect '/register'
        return nil
      end

      if username.length < 3 || username.length > 50
        r.flash['error'] = 'Username must be between 3 and 50 characters'
        r.redirect '/register'
        return nil
      end

      if password.length < 8
        r.flash['error'] = 'Password must be at least 8 characters long'
        r.redirect '/register'
        return nil
      end

      if DB[:accounts].where(username: username).count.positive?
        r.flash['error'] = 'Username already taken'
        r.redirect '/register'
        return nil
      end

      { username: username, password: password, key_text: key_text }
    end

    def self.create_unverified_account(r, params, fingerprint)
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

      r.session[:unverified_account_id] = id
      r.redirect '/verify-pgp'
    end

    def self.handle_verification_get(account_id)
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

    def self.handle_verification_post(r, account_id)
      if RateLimit.blocked?(client_ip, 'verify_pgp')
        r.flash['error'] = rate_limit_message('verify_pgp', client_ip)
        r.redirect '/verify-pgp'
      end

      RateLimit.record_attempt(client_ip, 'verify_pgp')
      submitted_code = r.params['code'].to_s.strip

      account = DB[:accounts].where(id: account_id).first

      unless account[:verification_expires_at] &&
             account[:verification_expires_at] > Time.now
        r.flash['error'] = 'Verification expired. Please try again.'
        r.redirect '/verify-pgp'
      end

      if submitted_code == account[:verification_code]
        complete_verification(r, account_id)
      else
        r.flash['error'] = 'Incorrect code. Please try again.'
        r.redirect '/verify-pgp'
      end
    end

    def self.complete_verification(r, account_id)
      DB[:accounts].where(id: account_id).update(
        verified: true,
        verification_code: nil,
        verification_expires_at: nil
      )

      3.times { create_secure_session(account_id) }

      r.session.delete(:unverified_account_id)
      r.flash['notice'] = 'Account created and verified successfully!'
      r.redirect '/dashboard'
    end
  end
end
