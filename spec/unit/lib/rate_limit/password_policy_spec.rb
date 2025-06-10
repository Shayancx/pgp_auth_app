# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RateLimit::PasswordPolicy do
  let(:username) { 'testuser' }

  before(:each) do
    DB[:rate_limits].delete
    DB[:accounts].delete
  end

  describe '.pgp_only_required?' do
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
    end
  end
end
