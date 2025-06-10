# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Dashboard Routes' do
  include Rack::Test::Methods

  let(:test_key) { File.read('spec/fixtures/test_public_key.asc') }
  let(:test_fingerprint) { GPGME::Key.import(test_key).imports.first.fingerprint }

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

  describe 'Session Management' do
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
        token = SessionManager.create_session(account_id, '192.168.1.1', 'Other Browser')

        post '/sessions/revoke', token: token

        expect(last_response.status).to eq(302)
        follow_redirect!
        expect(last_response.body).to include('Session revoked successfully')
      end
    end
  end
end
