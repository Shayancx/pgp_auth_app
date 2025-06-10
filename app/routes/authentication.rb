# frozen_string_literal: true

# Routes for user authentication (login/logout)
module Routes
  # Authentication routes handling login flow
  module Authentication
    def self.registered(app)
      app.instance_eval do
        # Step 1: Username-only login
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

        # Step 2a: Password entry (normal flow)
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

        # Handle logout
        r.on 'logout' do
          r.get { view 'logout' }

          r.post do
            clear_session_and_logout
            flash['notice'] = 'You have been logged out'
            r.redirect '/'
          end
        end
      end
    end

    def self.handle_password_authentication(r, username)
      password = r.params['password'].to_s

      if password.empty?
        r.flash['error'] = 'Password is required'
        r.redirect '/login-password'
      end

      account = DB[:accounts].where(username: username, verified: true).first

      if account && BCrypt::Password.new(account[:password_hash]) == password
        r.session[:pending_account_id] = account[:id]
        r.session.delete(:login_username)
        r.redirect '/pgp-2fa'
      else
        pgp_only_triggered = RateLimit.record_password_failure(username)

        if pgp_only_triggered
          r.flash['notice'] = 'Too many password failures. ' \
                              'This account now requires PGP-only authentication.'
          r.session[:pgp_only_account_id] = account[:id] if account
          r.session.delete(:login_username)
          r.redirect '/login-pgp-only'
        else
          r.flash['error'] = 'Invalid password'
          r.redirect '/login-password'
        end
      end
    end
  end
end
