# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RateLimit do
  let(:identifier) { '192.168.1.1' }
  let(:action) { 'login' }

  before(:each) do
    DB[:rate_limits].delete
  end

  describe '.blocked?' do
    context 'with no previous attempts' do
      it 'returns false' do
        expect(RateLimit.blocked?(identifier, action)).to be false
      end
    end

    context 'with attempts below limit' do
      it 'returns false' do
        3.times { RateLimit.record_attempt(identifier, action) }
        expect(RateLimit.blocked?(identifier, action)).to be false
      end
    end

    context 'with attempts at limit' do
      it 'returns true' do
        5.times { RateLimit.record_attempt(identifier, action) }
        expect(RateLimit.blocked?(identifier, action)).to be true
      end
    end

    context 'with expired block' do
      it 'returns false after block expires' do
        5.times { RateLimit.record_attempt(identifier, action) }

        # Fast forward past block time
        Timecop.travel(Time.now + 3600)
        expect(RateLimit.blocked?(identifier, action)).to be false
      end
    end
  end

  describe '.record_attempt' do
    it 'creates new record for first attempt' do
      expect do
        RateLimit.record_attempt(identifier, action)
      end.to change { DB[:rate_limits].count }.by(1)
    end

    it 'increments attempts within window' do
      RateLimit.record_attempt(identifier, action)
      RateLimit.record_attempt(identifier, action)

      record = DB[:rate_limits].where(identifier: identifier, action: action).first
      expect(record[:attempts]).to eq(2)
    end

    it 'resets attempts outside window' do
      RateLimit.record_attempt(identifier, action)

      # Travel past window
      Timecop.travel(Time.now + 3600)
      RateLimit.record_attempt(identifier, action)

      record = DB[:rate_limits].where(identifier: identifier, action: action).first
      expect(record[:attempts]).to eq(1)
    end

    it 'applies exponential backoff' do
      # Exceed limit
      6.times { RateLimit.record_attempt(identifier, action) }

      record = DB[:rate_limits].where(identifier: identifier, action: action).first
      expect(record[:blocked_until]).to be > Time.now
    end
  end

  describe '.time_until_retry' do
    it 'returns 0 when not blocked' do
      expect(RateLimit.time_until_retry(identifier, action)).to eq(0)
    end

    it 'returns seconds until unblock' do
      6.times { RateLimit.record_attempt(identifier, action) }

      time_remaining = RateLimit.time_until_retry(identifier, action)
      expect(time_remaining).to be > 0
    end
  end

  describe '.pgp_only_required?' do
    let(:username) { 'testuser' }

    context 'with no account' do
      it 'returns false' do
        expect(RateLimit.pgp_only_required?(username)).to be false
      end
    end

    context 'with normal account' do
      before do
        DB[:accounts].insert(
          username: username,
          password_hash: 'hash',
          public_key: 'key',
          fingerprint: 'fp',
          verified: true,
          pgp_only_mode: false,
          failed_password_count: 0
        )
      end

      it 'returns false when below threshold' do
        expect(RateLimit.pgp_only_required?(username)).to be false
      end

      it 'returns true when pgp_only_mode is set' do
        DB[:accounts].where(username: username).update(pgp_only_mode: true)
        expect(RateLimit.pgp_only_required?(username)).to be true
      end

      it 'returns true when failed count exceeds threshold' do
        DB[:accounts].where(username: username).update(failed_password_count: 10)
        expect(RateLimit.pgp_only_required?(username)).to be true
      end
    end
  end

  describe '.record_password_failure' do
    let(:username) { 'testuser' }

    before do
      DB[:accounts].insert(
        username: username,
        password_hash: 'hash',
        public_key: 'key',
        fingerprint: 'fp',
        verified: true,
        pgp_only_mode: false,
        failed_password_count: 0
      )
    end

    it 'increments failure count' do
      RateLimit.record_password_failure(username)

      account = DB[:accounts].where(username: username).first
      expect(account[:failed_password_count]).to eq(1)
    end

    it 'triggers PGP-only mode at threshold' do
      9.times { RateLimit.record_password_failure(username) }
      expect(RateLimit.record_password_failure(username)).to be true

      account = DB[:accounts].where(username: username).first
      expect(account[:pgp_only_mode]).to be true
    end
  end

  describe '.reset_password_failures' do
    let(:username) { 'testuser' }

    before do
      DB[:accounts].insert(
        username: username,
        password_hash: 'hash',
        public_key: 'key',
        fingerprint: 'fp',
        verified: true,
        pgp_only_mode: true,
        failed_password_count: 10
      )
    end

    it 'resets failure count and pgp_only_mode' do
      RateLimit.reset_password_failures(username)

      account = DB[:accounts].where(username: username).first
      expect(account[:failed_password_count]).to eq(0)
      expect(account[:pgp_only_mode]).to be false
    end
  end

  describe '.cleanup_old_records' do
    it 'removes records older than 24 hours' do
      # Create old record
      DB[:rate_limits].insert(
        identifier: identifier,
        action: action,
        attempts: 1,
        first_attempt_at: Time.now - 86_401,
        last_attempt_at: Time.now - 86_401
      )

      expect do
        RateLimit.cleanup_old_records
      end.to change { DB[:rate_limits].count }.by(-1)
    end
  end

  describe '.format_time_remaining' do
    it 'formats seconds correctly' do
      expect(RateLimit.format_time_remaining(30)).to eq('30 seconds')
    end

    it 'formats minutes correctly' do
      expect(RateLimit.format_time_remaining(120)).to eq('2 minutes')
    end

    it 'formats hours correctly' do
      expect(RateLimit.format_time_remaining(3600)).to eq('1 hours')
    end

    it 'formats hours and minutes correctly' do
      expect(RateLimit.format_time_remaining(3900)).to eq('1 hours and 5 minutes')
    end
  end
end
