# frozen_string_literal: true

require 'gpgme'
require 'securerandom'

module PgpAuth
  CRYPTO = GPGME::Crypto.new(always_trust: true)

  module_function

  # Import the ASCII-armored public key; returns its fingerprint.
  def import_and_fingerprint(armored)
    res = GPGME::Key.import(armored)
    res.imports.first.fingerprint
  end

  # Encrypt +plaintext+ for the key identified by +fingerprint+.
  def encrypt_for(fingerprint, plaintext)
    key = GPGME::Key.find(:public, fingerprint).first or
      raise "public key #{fingerprint} not found"
    CRYPTO.encrypt(plaintext, recipients: key, armor: true).to_s
  end

  # 32-char random challenge
  def random_code
    SecureRandom.alphanumeric(32)
  end
end
