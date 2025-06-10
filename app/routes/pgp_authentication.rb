# frozen_string_literal: true

# Routes for PGP-based authentication
module Routes
  # PGP authentication routes for 2FA and PGP-only mode
  module PgpAuthentication
    def self.registered(app)
      app.instance_eval do
        # Step 2b: PGP-only authentication (security escalation)
        r.on 'login-pgp-only' do
          account_id = session[:pgp_only_account_id]
          r.redirect '/login' unless account_id

          @account = DB[:accounts].where(id: account_id).first
          r.redirect '/login' unless @account

          r.get do
            handle_pgp_only_get(account_id)
          end

          r.post do
            handle_pgp_only_post(r, account_id)
          end
        end

        # Normal 2FA flow (after password authentication)
        r.on 'pgp-2fa' do
          account_id = session[:pending_account_id]
          r.redirect '/login' unless account_id

          @account = DB[:accounts].where(id: account_id).first
          r.redirect '/login' unless @account

          r.get do
            handle_2fa_get(account_id)
          end

          r.post do
            handle_2fa_post(r, account_id)
          end
        end
      end
    end

    def self.handle_pgp_only_get(account_id)
      if RateLimit.blocked?(account_id.to_s, '2fa')
        @blocked_message = rate_limit_message('2fa', account_id.to_s)
        view 'pgp_blocked'
      else
        generate_pgp_challenge(account_id)
        view 'login_pgp_only'
      end
    end

    def self.handle_pgp_only_post(r, account_id)
      if RateLimit.blocked?(account_id.to_s, '2fa')
        r.flash['error'] = rate_limit_message('2fa', account_id.to_s)
        r.redirect '/login-pgp-only'
      end

      submitted_code = r.params['code'].to_s.strip
      RateLimit.record_attempt(account_id.to_s, '2fa')

      if verify_pgp_challenge(account_id, submitted_code)
        RateLimit.reset_password_failures(@account[:username])
        DB[:challenges].where(account_id: account_id).delete

        3.times { create_secure_session(account_id) }

        r.session.delete(:pgp_only_account_id)
        r.session.delete(:login_username)
        r.flash['notice'] = 'PGP authentication successful - account security restored'
        r.redirect '/dashboard'
      else
        r.flash['error'] = 'Incorrect PGP code. Please try again.'
        r.redirect '/login-pgp-only'
      end
    end

    def self.handle_2fa_get(account_id)
      if RateLimit.blocked?(account_id.to_s, '2fa')
        @blocked_message = rate_limit_message('2fa', account_id.to_s)
        view 'pgp_blocked'
      else
        generate_pgp_challenge(account_id)
        view 'pgp_2fa'
      end
    end

    def self.handle_2fa_post(r, account_id)
      if RateLimit.blocked?(account_id.to_s, '2fa')
        r.flash['error'] = rate_limit_message('2fa', account_id.to_s)
        r.redirect '/pgp-2fa'
      end

      submitted_code = r.params['code'].to_s.strip
      RateLimit.record_attempt(account_id.to_s, '2fa')

      if verify_pgp_challenge(account_id, submitted_code)
        DB[:challenges].where(account_id: account_id).delete

        3.times { create_secure_session(account_id) }

        r.session.delete(:pending_account_id)
        r.flash['notice'] = 'Authentication successful'
        r.redirect '/dashboard'
      else
        r.flash['error'] = 'Incorrect code. Please try again.'
        r.redirect '/pgp-2fa'
      end
    end

    def self.generate_pgp_challenge(account_id)
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

    def self.verify_pgp_challenge(account_id, submitted_code)
      row = DB[:challenges].where(account_id: account_id)
                           .reverse(:id).first

      row && row[:expires_at] > Time.now && submitted_code == row[:code]
    end
  end
end
