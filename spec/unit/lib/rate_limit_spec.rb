# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RateLimit do
  describe '.cleanup_old_records' do
    it 'removes records older than 24 hours' do
      DB[:rate_limits].insert(
        identifier: 'test',
        action: 'login',
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
  end
end
