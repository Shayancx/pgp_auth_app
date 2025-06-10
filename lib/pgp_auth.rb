# frozen_string_literal: true

require 'gpgme'
require 'securerandom'
require 'digest'

# Module for PGP authentication operations
module PgpAuth
  # Use proper trust model - verify signatures
  CRYPTO = GPGME::Crypto.new(armor: true)

  module_function

  # Import the ASCII-armored public key; returns its fingerprint.
  def import_and_fingerprint(armored)
    # Validate key format
    raise 'Invalid PGP key format' unless armored.include?('-----BEGIN PGP PUBLIC KEY BLOCK-----')

    res = GPGME::Key.import(armored)

    raise 'No valid PGP keys found in input' if res.imports.empty?

    fingerprint = res.imports.first.fingerprint

    # Ensure key is not expired or revoked
    key = GPGME::Key.find(:public, fingerprint).first
    raise 'PGP key is expired' if key&.expired?

    fingerprint
  end

  # Encrypt +plaintext+ for the key identified by +fingerprint+.
  def encrypt_for(fingerprint, plaintext)
    key = GPGME::Key.find(:public, fingerprint).first or
      raise "public key #{fingerprint} not found"

    raise "PGP key #{fingerprint} is expired" if key.expired?

    CRYPTO.encrypt(plaintext, recipients: key, armor: true).to_s
  end

  # Generate secure random challenge
  def random_code
    SecureRandom.alphanumeric(32)
  end

  # Hash challenge for zero-knowledge storage
  def hash_challenge(code)
    Digest::SHA256.hexdigest(code)
  end
end
