# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Registration Routes' do
  include Rack::Test::Methods

  let(:test_key) { File.read('spec/fixtures/test_public_key.asc') }
  let(:test_fingerprint) { GPGME::Key.import(test_key).imports.first.fingerprint }

  describe 'Registration flow' do
    describe 'GET /register' do
      it 'shows registration form' do
        get '/register'
        expect(last_response).to be_ok
        expect(last_response.body).to include('Create Account')
      end

      it 'shows rate limit message when blocked' do
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
    end
  end
end
