# frozen_string_literal: true

require 'spec_helper'

RSpec.describe App do
  include Rack::Test::Methods

  let(:test_key) { File.read('spec/fixtures/test_public_key.asc') }
  let(:test_fingerprint) { GPGME::Key.import(test_key).imports.first.fingerprint }

  describe 'GET /' do
    it 'shows home page' do
      get '/'
      expect(last_response).to be_ok
      expect(last_response.body).to include('PGP Auth')
      expect(last_response.body).to include('Login')
      expect(last_response.body).to include('Register')
    end
  end

  describe 'Registration flow' do
    describe 'GET /register' do
      it 'shows registration form' do
        get '/register'
        expect(last_response).to be_ok
        expect(last_response.body).to include('Create Account')
      end

      it 'shows rate limit message when blocked' do
        # Simulate rate limit
        4.times do
          post '/register', username: 'test', password: 'pass', public_key: 'key'
        end

        get '/register'
        expect(last_response.body).to include('Too many registration attempts')
      end
    end

    describe 'POST /register' do
      let(:valid_params) do
        {
          username: 'newuser',
          password: 'password123',
          public_key: test_key
        }
      end

      it 'creates unverified account with valid data' do
        expect do
          post '/register', valid_params
        end.to change { DB[:accounts].count }.by(1)

        expect(last_response.status).to eq(302)
        expect(last_response.location).to include('/verify-pgp')

        account = DB[:accounts].order(:id).last
        expect(account[:verified]).to be false
      end

      it 'rejects empty username' do
        post '/register', valid_params.merge(username: '')

        expect(last_response.status).to eq(302)
        follow_redirect!
        expect(last_response.body).to include('All fields are required')
      end

      it 'rejects short username' do
        post '/register', valid_params.merge(username: 'ab')

        follow_redirect!
        expect(last_response.body).to include('Username must be between 3 and 50 characters')
      end

      it 'rejects short password' do
        post '/register', valid_params.merge(password: 'short')

        follow_redirect!
        expect(last_response.body).to include('Password must be at least 8 characters')
      end

      it 'rejects duplicate username' do
        post '/register', valid_params
        clear_cookies

        post '/register', valid_params
        follow_redirect!
        expect(last_response.body).to include('Username already taken')
      end

      it 'rejects invalid PGP key' do
        post '/register', valid_params.merge(public_key: 'invalid key')

        follow_redirect!
        expect(last_response.body).to include('Invalid PGP key')
      end

      it 'enforces rate limiting' do
        4.times do |i|
          post '/register', valid_params.merge(username: "user#{i}")
          clear_cookies
        end

        follow_redirect!
        expect(last_response.body).to include('Too many registration attempts')
      end
    end

    describe 'PGP verification' do
      before do
        post '/register', {
          username: 'newuser',
          password: 'password123',
          public_key: test_key
        }
      end

      describe 'GET /verify-pgp' do
        it 'shows verification challenge' do
          get '/verify-pgp'
          expect(last_response).to be_ok
          expect(last_response.body).to include('Verify Your PGP Key')
          expect(last_response.body).to include('-----BEGIN PGP MESSAGE-----')
        end

        it 'redirects if no pending registration' do
          clear_cookies
          get '/verify-pgp'

          expect(last_response.status).to eq(302)
          follow_redirect!
          expect(last_response.body).to include('No pending registration found')
        end
      end

      describe 'POST /verify-pgp' do
        it 'verifies account with correct code' do
          get '/verify-pgp'
          last_response.body.match(%r{<pre class="encrypted-text">(.*?)</pre>}m)[1]

          # In real scenario, would decrypt with private key
          # For testing, extract from DB
          account_id = rack_mock_session.cookie_jar['rack.session']['unverified_account_id']
          account = DB[:accounts].where(id: account_id).first
          code = account[:verification_code]

          post '/verify-pgp', code: code

          expect(last_response.status).to eq(302)
          expect(last_response.location).to include('/dashboard')

          account = DB[:accounts].where(id: account_id).first
          expect(account[:verified]).to be true
        end

        it 'rejects incorrect code' do
          post '/verify-pgp', code: 'wrong_code'

          follow_redirect!
          expect(last_response.body).to include('Incorrect code')
        end
      end
    end
  end

  describe 'Login flow' do
    let!(:account) do
      DB[:accounts].insert(
        username: 'testuser',
        password_hash: BCrypt::Password.create('password123'),
        public_key: test_key,
        fingerprint: test_fingerprint,
        verified: true,
        pgp_only_mode: false,
        failed_password_count: 0
      )
    end

    describe 'Step 1: Username' do
      describe 'GET /login' do
        it 'shows login form' do
          get '/login'
          expect(last_response).to be_ok
          expect(last_response.body).to include('Sign In')
        end
      end

      describe 'POST /login' do
        it 'proceeds to password with valid username' do
          post '/login', username: 'testuser'

          expect(last_response.status).to eq(302)
          expect(last_response.location).to include('/login-password')
        end

        it 'rejects invalid username' do
          post '/login', username: 'nonexistent'

          follow_redirect!
          expect(last_response.body).to include('Invalid username')
        end

        it 'redirects to PGP-only for flagged accounts' do
          DB[:accounts].where(id: account).update(pgp_only_mode: true)

          post '/login', username: 'testuser'

          expect(last_response.location).to include('/login-pgp-only')
        end
      end
    end

    describe 'Step 2: Password' do
      before { post '/login', username: 'testuser' }

      describe 'GET /login-password' do
        it 'shows password form' do
          get '/login-password'
          expect(last_response).to be_ok
          expect(last_response.body).to include('Enter Password')
          expect(last_response.body).to include('Welcome back, testuser')
        end
      end

      describe 'POST /login-password' do
        it 'proceeds to 2FA with correct password' do
          post '/login-password', password: 'password123'

          expect(last_response.status).to eq(302)
          expect(last_response.location).to include('/pgp-2fa')
        end

        it 'rejects incorrect password' do
          post '/login-password', password: 'wrong'

          follow_redirect!
          expect(last_response.body).to include('Invalid password')
        end

        it 'triggers PGP-only mode after threshold' do
          # Fail 9 times
          9.times do
            post '/login-password', password: 'wrong'
          end

          # 10th failure triggers PGP-only
          post '/login-password', password: 'wrong'

          expect(last_response.location).to include('/login-pgp-only')
          follow_redirect!
          expect(last_response.body).to include('Too many password failures')
        end
      end
    end

    describe 'Step 3: PGP 2FA' do
      before do
        post '/login', username: 'testuser'
        post '/login-password', password: 'password123'
      end

      describe 'GET /pgp-2fa' do
        it 'shows PGP challenge' do
          get '/pgp-2fa'
          expect(last_response).to be_ok
          expect(last_response.body).to include('Two-Factor Authentication')
          expect(last_response.body).to include('-----BEGIN PGP MESSAGE-----')
        end
      end

      describe 'POST /pgp-2fa' do
        it 'logs in with correct code' do
          get '/pgp-2fa'

          # Extract challenge from DB
          account_id = rack_mock_session.cookie_jar['rack.session']['pending_account_id']
          challenge = DB[:challenges].where(account_id: account_id).order(:id).last

          post '/pgp-2fa', code: challenge[:code]

          expect(last_response.status).to eq(302)
          expect(last_response.location).to include('/dashboard')
        end

        it 'rejects incorrect code' do
          post '/pgp-2fa', code: 'wrong_code'

          follow_redirect!
          expect(last_response.body).to include('Incorrect code')
        end
      end
    end

    describe 'PGP-only authentication' do
      before do
        DB[:accounts].where(id: account).update(pgp_only_mode: true)
        post '/login', username: 'testuser'
      end

      describe 'GET /login-pgp-only' do
        it 'shows PGP-only challenge' do
          get '/login-pgp-only'
          expect(last_response).to be_ok
          expect(last_response.body).to include('PGP-Only Authentication')
          expect(last_response.body).to include('Enhanced Security Mode')
        end
      end

      describe 'POST /login-pgp-only' do
        it 'authenticates and resets pgp-only mode' do
          get '/login-pgp-only'

          # Get challenge code
          account_id = rack_mock_session.cookie_jar['rack.session']['pgp_only_account_id']
          challenge = DB[:challenges].where(account_id: account_id).order(:id).last

          post '/login-pgp-only', code: challenge[:code]

          expect(last_response.status).to eq(302)
          expect(last_response.location).to include('/dashboard')

          # Check pgp-only mode was reset
          updated = DB[:accounts].where(id: account).first
          expect(updated[:pgp_only_mode]).to be false
          expect(updated[:failed_password_count]).to eq(0)
        end
      end
    end
  end

  describe 'Authenticated routes' do
    let!(:account_id) do
      DB[:accounts].insert(
        username: 'authuser',
        password_hash: BCrypt::Password.create('password123'),
        public_key: test_key,
        fingerprint: test_fingerprint,
        verified: true,
        pgp_only_mode: false,
        failed_password_count: 0
      )
    end

    before do
      # Complete login flow
      post '/login', username: 'authuser'
      post '/login-password', password: 'password123'
      get '/pgp-2fa'

      challenge = DB[:challenges].where(account_id: account_id).order(:id).last
      post '/pgp-2fa', code: challenge[:code]
    end

    describe 'GET /dashboard' do
      it 'shows dashboard for logged in user' do
        get '/dashboard'
        expect(last_response).to be_ok
        expect(last_response.body).to include('Welcome, authuser')
        expect(last_response.body).to include('Secure Dashboard')
      end

      it 'redirects when not logged in' do
        clear_cookies
        get '/dashboard'

        expect(last_response.status).to eq(302)
        expect(last_response.location).to include('/login')
      end
    end

    describe 'GET /sessions' do
      it 'shows active sessions' do
        get '/sessions'
        expect(last_response).to be_ok
        expect(last_response.body).to include('Active Sessions')
        expect(last_response.body).to include('Current Session')
      end
    end

    describe 'POST /sessions/revoke' do
      it 'revokes specified session' do
        # Create another session
        token = SessionManager.create_session(account_id, '192.168.1.1', 'Other Browser')

        post '/sessions/revoke', token: token

        expect(last_response.status).to eq(302)
        follow_redirect!
        expect(last_response.body).to include('Session revoked successfully')
      end
    end

    describe 'GET /security' do
      it 'shows security dashboard' do
        get '/security'
        expect(last_response).to be_ok
        expect(last_response.body).to include('Security Dashboard')
        expect(last_response.body).to include('Account Status')
        expect(last_response.body).to include('Recent Activity')
      end
    end

    describe 'Logout' do
      describe 'GET /logout' do
        it 'shows logout confirmation' do
          get '/logout'
          expect(last_response).to be_ok
          expect(last_response.body).to include('Are you sure you want to sign out?')
        end
      end

      describe 'POST /logout' do
        it 'logs out and revokes session' do
          post '/logout'

          expect(last_response.status).to eq(302)
          expect(last_response.location).to include('/')

          # Try accessing protected route
          get '/dashboard'
          expect(last_response.status).to eq(302)
        end
      end
    end
  end

  describe 'Security features' do
    describe 'CSRF protection' do
      it 'rejects POST without CSRF token' do
        # Manually craft request without middleware
        post_request = Rack::MockRequest.new(app)
        response = post_request.post('/login', params: { username: 'test' })

        expect(response.status).to eq(403)
      end
    end

    describe 'Session security' do
      it 'expires sessions after timeout' do
        # Login
        account_id = DB[:accounts].insert(
          username: 'expiretest',
          password_hash: BCrypt::Password.create('password123'),
          public_key: test_key,
          fingerprint: test_fingerprint,
          verified: true,
          session_timeout_hours: 1
        )

        post '/login', username: 'expiretest'
        post '/login-password', password: 'password123'
        get '/pgp-2fa'
        challenge = DB[:challenges].where(account_id: account_id).order(:id).last
        post '/pgp-2fa', code: challenge[:code]

        # Access works initially
        get '/dashboard'
        expect(last_response).to be_ok

        # Fast forward past timeout
        Timecop.travel(Time.now + 2 * 3600)

        # Session should be invalid
        get '/dashboard'
        expect(last_response.status).to eq(302)
      end
    end
  end
end
