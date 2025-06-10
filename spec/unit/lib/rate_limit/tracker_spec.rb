# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RateLimit::Tracker do
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
end
