# frozen_string_literal: true

require 'spec_helper'

RSpec.describe App do
  include Rack::Test::Methods

  describe 'GET /' do
    it 'shows home page' do
      get '/'
      expect(last_response).to be_ok
      expect(last_response.body).to include('PGP Auth')
      expect(last_response.body).to include('Login')
      expect(last_response.body).to include('Register')
    end
  end

  describe 'Security features' do
    describe 'CSRF protection' do
      it 'rejects POST without CSRF token' do
        post_request = Rack::MockRequest.new(app)
        response = post_request.post('/login', params: { username: 'test' })

        expect(response.status).to eq(403)
      end
    end

    describe 'Session security' do
      let(:test_key) { File.read('spec/fixtures/test_public_key.asc') }
      let(:test_fingerprint) { GPGME::Key.import(test_key).imports.first.fingerprint }

      it 'expires sessions after timeout' do
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

        get '/dashboard'
        expect(last_response).to be_ok

        Timecop.travel(Time.now + 2 * 3600)

        get '/dashboard'
        expect(last_response.status).to eq(302)
      end
    end
  end
end
