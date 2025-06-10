# frozen_string_literal: true

FactoryBot.define do
  factory :account, class: OpenStruct do
    sequence(:username) { |n| "user#{n}" }
    password_hash { BCrypt::Password.create('password123') }
    public_key { File.read('spec/fixtures/test_public_key.asc') }
    fingerprint { '1234567890ABCDEF1234567890ABCDEF12345678' }
    verified { true }
    pgp_only_mode { false }
    failed_password_count { 0 }
    session_timeout_hours { 24 }
    max_concurrent_sessions { 5 }

    trait :unverified do
      verified { false }
    end

    trait :pgp_only do
      pgp_only_mode { true }
    end

    trait :with_failed_attempts do
      failed_password_count { 5 }
    end

    to_create do |instance|
      DB[:accounts].insert(instance.to_h)
    end
  end
end
