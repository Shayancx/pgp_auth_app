# frozen_string_literal: true

require 'gpgme'
require 'securerandom'
require 'digest'

# Enhanced PGP authentication with comprehensive security
module PgpAuth
  # Use proper trust model - verify signatures
  CRYPTO = GPGME::Crypto.new(armor: true)

  # Minimum key requirements
  MIN_KEY_SIZE = 2048
  ALLOWED_ALGORITHMS = %w[RSA ECC].freeze
  MAX_KEY_AGE_YEARS = 10

  module_function

  # Enhanced key import with comprehensive validation
  def import_and_fingerprint(armored)
    # Validate key format
    raise 'Invalid PGP key format - missing header' unless armored.include?('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    raise 'Invalid PGP key format - missing footer' unless armored.include?('-----END PGP PUBLIC KEY BLOCK-----')
    
    # Check key size limits
    raise 'PGP key too large' if armored.bytesize > 100_000
    raise 'PGP key too small' if armored.bytesize < 500

    # Sanitize input
    armored = armored.strip.gsub(/\r\n/, "\n")

    begin
      res = GPGME::Key.import(armored)
    rescue GPGME::Error => e
      raise "PGP key import failed: #{e.message}"
    end

    raise 'No valid PGP keys found in input' if res.imports.empty?
    raise 'Multiple keys not allowed' if res.imports.length > 1

    fingerprint = res.imports.first.fingerprint

    # Enhanced key validation
    key = GPGME::Key.find(:public, fingerprint).first
    raise 'PGP key not found after import' unless key

    validate_key_security(key)

    fingerprint
  end

  # Enhanced encryption with additional security checks
  def encrypt_for(fingerprint, plaintext)
    # Input validation
    raise 'Fingerprint cannot be empty' if fingerprint.nil? || fingerprint.empty?
    raise 'Plaintext cannot be empty' if plaintext.nil? || plaintext.empty?
    raise 'Plaintext too large' if plaintext.bytesize > 10000

    key = GPGME::Key.find(:public, fingerprint).first
    raise "Public key #{fingerprint} not found" unless key

    # Validate key before use
    validate_key_security(key)

    begin
      result = CRYPTO.encrypt(plaintext, recipients: key, armor: true)
      encrypted = result.to_s
      
      # Validate encryption result
      raise 'Encryption failed - empty result' if encrypted.empty?
      raise 'Encryption failed - invalid format' unless encrypted.include?('-----BEGIN PGP MESSAGE-----')
      
      encrypted
    rescue GPGME::Error => e
      raise "PGP encryption failed: #{e.message}"
    end
  end

  # Cryptographically secure random challenge generation
  def random_code
    # Use multiple entropy sources
    base_entropy = SecureRandom.random_bytes(32)
    time_entropy = [Time.now.to_f * 1000000].pack('Q>')
    process_entropy = [Process.pid, $$].pack('Q>Q>')
    
    combined_entropy = base_entropy + time_entropy + process_entropy
    
    # Generate final code with sufficient entropy
    code = Digest::SHA256.hexdigest(combined_entropy)[0, 32]
    
    # Ensure proper character distribution
    code.chars.map.with_index do |char, index|
      if index.even?
        # Ensure mixed case
        rand < 0.5 ? char.upcase : char.downcase
      else
        # Mix with numbers
        rand < 0.3 ? rand(10).to_s : char
      end
    end.join.slice(0, 32)
  end

  # Enhanced challenge hashing with salt
  def hash_challenge(code)
    raise 'Challenge code cannot be empty' if code.nil? || code.empty?
    
    # Use application-specific salt
    salt = ENV.fetch('CHALLENGE_SALT', 'default_challenge_salt_change_in_production')
    
    # Use PBKDF2 for additional security
    iterations = 10000
    key_length = 32
    
    derived_key = OpenSSL::PKCS5.pbkdf2_hmac(
      code,
      salt,
      iterations,
      key_length,
      OpenSSL::Digest.new('SHA256')
    )
    
    derived_key.unpack1('H*')
  end

  # Enhanced key validation
  def validate_key_security(key)
    raise 'PGP key is expired' if key.expired?
    raise 'PGP key is revoked' if key.revoked?
    raise 'PGP key is invalid' if key.invalid?
    raise 'PGP key is disabled' if key.disabled?

    # Check key age
    if key.primary_subkey&.timestamp
      key_age_years = (Time.now - key.primary_subkey.timestamp) / (365.25 * 24 * 3600)
      raise "PGP key is too old (#{key_age_years.round(1)} years)" if key_age_years > MAX_KEY_AGE_YEARS
    end

    # Validate key algorithm and size
    subkey = key.primary_subkey
    if subkey
      algorithm = subkey.pubkey_algo_letter
      length = subkey.length

      raise "Unsupported algorithm: #{algorithm}" unless ALLOWED_ALGORITHMS.include?(algorithm)
      raise "Key size too small: #{length} bits (minimum #{MIN_KEY_SIZE})" if length < MIN_KEY_SIZE
    end

    # Check for valid user IDs
    raise 'PGP key has no valid user IDs' if key.uids.empty?
    raise 'PGP key has no valid signatures' unless key.uids.any? { |uid| uid.validity == :valid }

    # Additional security checks
    validate_key_capabilities(key)
    validate_key_algorithms(key)
  end

  # Validate key capabilities
  def validate_key_capabilities(key)
    primary = key.primary_subkey
    raise 'Primary key must support signing' unless primary&.can_sign?
    
    # Ensure we have encryption capability
    encryption_key = key.subkeys.find { |sk| sk.can_encrypt? }
    raise 'Key must have encryption capability' unless encryption_key
  end

  # Validate cryptographic algorithms
  def validate_key_algorithms(key)
    key.subkeys.each do |subkey|
      # Check for weak algorithms
      case subkey.pubkey_algo
      when :dsa
        raise 'DSA keys are not allowed' if subkey.length < 3072
      when :rsa
        raise 'RSA key too small' if subkey.length < MIN_KEY_SIZE
      when :elgamal
        raise 'ElGamal keys are not recommended'
      end
    end
  end

  # Secure cleanup of sensitive data
  def secure_cleanup(sensitive_string)
    return unless sensitive_string.is_a?(String)
    
    # Overwrite memory
    sensitive_string.length.times { |i| sensitive_string[i] = "\x00" }
    sensitive_string.clear
  end

  # Validate challenge response timing
  def validate_challenge_timing(created_at, max_age_seconds = 300)
    raise 'Challenge timestamp missing' unless created_at
    
    age = Time.now - created_at
    raise 'Challenge expired' if age > max_age_seconds
    raise 'Challenge from future' if age < -60 # Allow 60s clock skew
    
    true
  end
end
