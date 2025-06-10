# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Authentication Routes' do
  include Rack::Test::Methods

  let(:test_key) { File.read('spec/fixtures/test_public_key.asc') }
  let(:test_fingerprint) { GPGME::Key.import(test_key).imports.first.fingerprint }

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
        9.times do
          post '/login-password', password: 'wrong'
        end

        post '/login-password', password: 'wrong'

        expect(last_response.location).to include('/login-pgp-only')
        follow_redirect!
        expect(last_response.body).to include('Too many password failures')
      end
    end
  end
end
