# frozen_string_literal: true

require 'spec_helper'

RSpec.describe SessionManager do
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

  describe '.cleanup_expired_sessions' do
    it 'marks expired sessions as revoked' do
      SessionManager.create_session(account_id, '127.0.0.1', 'Test')

      Timecop.travel(Time.now + 25 * 3600)
      result = SessionManager.cleanup_expired_sessions

      expect(result[:expired_sessions]).to eq(1)
    end
  end

  describe '.get_audit_log' do
    it 'returns audit logs for account' do
      SessionManager.create_session(account_id, '127.0.0.1', 'Test')

      logs = SessionManager.get_audit_log(account_id)

      expect(logs.size).to eq(1)
      expect(logs.first[:event_type]).to eq('login')
    end
  end
end
