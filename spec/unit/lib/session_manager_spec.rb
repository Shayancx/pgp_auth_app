# frozen_string_literal: true

require 'spec_helper'

RSpec.describe SessionManager do
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

    it 'respects max concurrent sessions' do
      # Create max sessions
      5.times do
        SessionManager.create_session(account_id, ip_address, user_agent)
      end

      # Creating one more should revoke the oldest
      expect do
        SessionManager.create_session(account_id, ip_address, user_agent)
      end.to change { DB[:audit_logs].where(event_type: 'session_revoked').count }.by(1)
    end

    it 'sets correct expiration time' do
      token = SessionManager.create_session(account_id, ip_address, user_agent)
      session = DB[:user_sessions].where(session_token: token).first

      expected_expiry = Time.now + (24 * 3600)
      expect(session[:expires_at]).to be_within(5).of(expected_expiry)
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

    it 'returns nil for expired session' do
      Timecop.travel(Time.now + 25 * 3600)
      result = SessionManager.validate_session(token, ip_address, user_agent)
      expect(result).to be_nil
    end

    it 'returns nil for revoked session' do
      SessionManager.revoke_session(token)
      result = SessionManager.validate_session(token, ip_address, user_agent)
      expect(result).to be_nil
    end

    it 'updates last accessed time' do
      original_time = DB[:user_sessions].where(session_token: token).first[:last_accessed_at]

      Timecop.travel(Time.now + 3600)
      SessionManager.validate_session(token, ip_address, user_agent)

      new_time = DB[:user_sessions].where(session_token: token).first[:last_accessed_at]
      expect(new_time).to be > original_time
    end
  end

  describe '.revoke_session' do
    let(:token) { SessionManager.create_session(account_id, ip_address, user_agent) }

    it 'marks session as revoked' do
      SessionManager.revoke_session(token)

      session = DB[:user_sessions].where(session_token: token).first
      expect(session[:revoked]).to be true
      expect(session[:revoked_at]).not_to be_nil
    end

    it 'logs the revocation' do
      expect do
        SessionManager.revoke_session(token, 'test_reason')
      end.to change { DB[:audit_logs].where(event_type: 'session_revoked').count }.by(1)
    end

    it 'returns false for non-existent session' do
      result = SessionManager.revoke_session('invalid_token')
      expect(result).to be false
    end
  end

  describe '.revoke_all_sessions' do
    before do
      3.times { SessionManager.create_session(account_id, ip_address, user_agent) }
    end

    it 'revokes all sessions for account' do
      count = SessionManager.revoke_all_sessions(account_id)

      expect(count).to eq(3)
      expect(DB[:user_sessions].where(account_id: account_id, revoked: false).count).to eq(0)
    end

    it 'can exclude a specific token' do
      tokens = DB[:user_sessions].where(account_id: account_id).map(:session_token)
      keep_token = tokens.first

      count = SessionManager.revoke_all_sessions(account_id, keep_token)

      expect(count).to eq(2)
      expect(DB[:user_sessions].where(session_token: keep_token, revoked: false).count).to eq(1)
    end
  end

  describe '.get_active_sessions' do
    it 'returns only active sessions' do
      active_token = SessionManager.create_session(account_id, ip_address, user_agent)
      revoked_token = SessionManager.create_session(account_id, ip_address, user_agent)
      SessionManager.revoke_session(revoked_token)

      sessions = SessionManager.get_active_sessions(account_id)

      expect(sessions.size).to eq(1)
      expect(sessions.first[:session_token]).to eq(active_token)
    end

    it 'orders by last accessed time descending' do
      token1 = SessionManager.create_session(account_id, ip_address, user_agent)

      Timecop.travel(Time.now + 3600)
      token2 = SessionManager.create_session(account_id, ip_address, user_agent)

      sessions = SessionManager.get_active_sessions(account_id)

      expect(sessions.first[:session_token]).to eq(token2)
      expect(sessions.last[:session_token]).to eq(token1)
    end
  end

  describe '.cleanup_expired_sessions' do
    it 'marks expired sessions as revoked' do
      token = SessionManager.create_session(account_id, ip_address, user_agent)

      Timecop.travel(Time.now + 25 * 3600)
      result = SessionManager.cleanup_expired_sessions

      expect(result[:expired_sessions]).to eq(1)

      session = DB[:user_sessions].where(session_token: token).first
      expect(session[:revoked]).to be true
    end

    it 'deletes old audit logs' do
      # Create old audit log
      DB[:audit_logs].insert(
        account_id: account_id,
        event_type: 'login',
        created_at: Time.now - 91 * 24 * 3600
      )

      result = SessionManager.cleanup_expired_sessions
      expect(result[:old_logs]).to eq(1)
    end
  end

  describe '.get_audit_log' do
    it 'returns audit logs for account' do
      SessionManager.create_session(account_id, ip_address, user_agent)
      SessionManager.create_session(account_id, ip_address, user_agent)

      logs = SessionManager.get_audit_log(account_id)

      expect(logs.size).to eq(2)
      expect(logs.all? { |log| log[:event_type] == 'login' }).to be true
    end

    it 'respects limit parameter' do
      5.times { SessionManager.create_session(account_id, ip_address, user_agent) }

      logs = SessionManager.get_audit_log(account_id, 3)
      expect(logs.size).to eq(3)
    end

    it 'orders by created_at descending' do
      SessionManager.create_session(account_id, ip_address, user_agent)

      Timecop.travel(Time.now + 3600)
      SessionManager.log_event(account_id, 'test_event', nil, nil, {})

      logs = SessionManager.get_audit_log(account_id)
      expect(logs.first[:event_type]).to eq('test_event')
    end
  end
end
