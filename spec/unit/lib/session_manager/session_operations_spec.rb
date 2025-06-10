# frozen_string_literal: true

require 'spec_helper'

RSpec.describe SessionManager::SessionOperations do
  let(:account_id) { 1 }
  let(:ip_address) { '192.168.1.1' }
  let(:user_agent) { 'Mozilla/5.0 (Test Browser)' }

  before(:each) do
    DB[:accounts].insert(
      id: account_id,
      username: 'testuser',
      password_hash: 'hash',
      public_key: 'key',
      fingerprint: 'fp',
      verified: true,
      session_timeout_hours: 24,
      max_concurrent_sessions: 5
    )
  end

  describe '.create_session' do
    it 'creates a new session token' do
      token = SessionManager.create_session(account_id, ip_address, user_agent)

      expect(token).to match(/^[a-f0-9]{64}$/)
      expect(DB[:user_sessions].count).to eq(1)
    end

    it 'logs the login event' do
      expect do
        SessionManager.create_session(account_id, ip_address, user_agent)
      end.to change { DB[:audit_logs].count }.by(1)

      log = DB[:audit_logs].first
      expect(log[:event_type]).to eq('login')
    end
  end

  describe '.validate_session' do
    let(:token) { SessionManager.create_session(account_id, ip_address, user_agent) }

    it 'returns account_id for valid session' do
      result = SessionManager.validate_session(token, ip_address, user_agent)
      expect(result).to eq(account_id)
    end

    it 'returns nil for invalid token' do
      result = SessionManager.validate_session('invalid', ip_address, user_agent)
      expect(result).to be_nil
    end
  end
end
