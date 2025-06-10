require 'spec_helper'

RSpec.describe SessionMiddleware do
  let(:app) { ->(env) { [200, {}, ['OK']] } }
  let(:middleware) { SessionMiddleware.new(app) }
  let(:account_id) { 1 }
  
  before(:each) do
    DB[:accounts].insert(
      id: account_id,
      username: 'testuser',
      password_hash: 'hash',
      public_key: 'key',
      fingerprint: 'fp',
      verified: true
    )
  end

  def make_request(path, session = {})
    env = Rack::MockRequest.env_for(path)
    env['rack.session'] = session
    env['HTTP_USER_AGENT'] = 'Test Browser'
    env['REMOTE_ADDR'] = '127.0.0.1'
    middleware.call(env)
  end

  describe 'for public paths' do
    %w[/ /login /register /verify-pgp].each do |path|
      it "skips validation for #{path}" do
        status, _, _ = make_request(path)
        expect(status).to eq(200)
      end
    end
  end

  describe 'for protected paths' do
    it 'validates session token if present' do
      token = SessionManager.create_session(account_id, '127.0.0.1', 'Test Browser')
      
      status, env, _ = make_request('/dashboard', session_token: token)
      
      expect(status).to eq(200)
      expect(env['authenticated_account_id']).to eq(account_id)
    end

    it 'clears invalid session' do
      session = { session_token: 'invalid_token' }
      
      status, env, _ = make_request('/dashboard', session)
      
      expect(status).to eq(200)
      expect(session).to be_empty
      expect(env['session_expired']).to be true
    end

    it 'allows request without session token' do
      status, _, _ = make_request('/dashboard')
      expect(status).to eq(200)
    end
  end
end
