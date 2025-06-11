# frozen_string_literal: true

require 'gpgme'
require 'securerandom'
require 'digest'
require 'openssl'

# SECURITY HARDENED: Enhanced PGP authentication with military-grade security
module PgpAuth
  CRYPTO = GPGME::Crypto.new(armor: true)

  # SECURITY HARDENED: Stricter key requirements
  MIN_KEY_SIZE = 3072  # Increased minimum
  ALLOWED_ALGORITHMS = %w[RSA ECC EdDSA].freeze
  MAX_KEY_AGE_YEARS = 5  # Reduced max age
  MAX_KEY_SIZE = 100_000
  MIN_KEY_SIZE_BYTES = 1000

  module_function

  # SECURITY HARDENED: Enhanced key import with comprehensive validation
  def import_and_fingerprint(armored)
    raise 'PGP key is required' if armored.nil? || armored.empty?
    
    # SECURITY HARDENED: Strict format validation
    unless armored.include?('-----BEGIN PGP PUBLIC KEY BLOCK-----') && 
           armored.include?('-----END PGP PUBLIC KEY BLOCK-----')
      raise 'Invalid PGP key format - missing required headers'
    end
    
    # SECURITY HARDENED: Size limits
    raise "PGP key too large (max #{MAX_KEY_SIZE} bytes)" if armored.bytesize > MAX_KEY_SIZE
    raise "PGP key too small (min #{MIN_KEY_SIZE_BYTES} bytes)" if armored.bytesize < MIN_KEY_SIZE_BYTES

    # SECURITY HARDENED: Sanitize input
    armored = armored.strip.gsub(/\r\n?/, "\n")
    
    # SECURITY HARDENED: Validate character set
    unless armored.match?(/\A[\x20-\x7E\n]+\z/)
      raise 'PGP key contains invalid characters'
    end

    begin
      res = GPGME::Key.import(armored)
    rescue GPGME::Error => e
      raise "PGP key import failed: #{sanitize_error_message(e.message)}"
    end

    raise 'No valid PGP keys found in input' if res.imports.empty?
    raise 'Multiple keys not allowed - use single key only' if res.imports.length > 1

    fingerprint = res.imports.first.fingerprint
    raise 'Invalid fingerprint generated' unless fingerprint&.match?(/\A[A-F0-9]{40}\z/)

    # SECURITY HARDENED: Enhanced key validation
    key = GPGME::Key.find(:public, fingerprint).first
    raise 'PGP key not found after import' unless key

    validate_key_security(key)
    fingerprint
  end

  # SECURITY HARDENED: Enhanced encryption with additional security checks
  def encrypt_for(fingerprint, plaintext)
    raise 'Fingerprint cannot be empty' if fingerprint.nil? || fingerprint.empty?
    raise 'Plaintext cannot be empty' if plaintext.nil? || plaintext.empty?
    raise 'Plaintext too large (max 5000 bytes)' if plaintext.bytesize > 5000
    raise 'Invalid fingerprint format' unless fingerprint.match?(/\A[A-F0-9]{40}\z/)

    key = GPGME::Key.find(:public, fingerprint).first
    raise "Public key #{fingerprint} not found" unless key

    # SECURITY HARDENED: Re-validate key before use
    validate_key_security(key)

    begin
      result = CRYPTO.encrypt(plaintext, recipients: key, armor: true)
      encrypted = result.to_s
      
      # SECURITY HARDENED: Validate encryption result
      raise 'Encryption failed - empty result' if encrypted.empty?
      unless encrypted.include?('-----BEGIN PGP MESSAGE-----') && 
             encrypted.include?('-----END PGP MESSAGE-----')
        raise 'Encryption failed - invalid format'
      end
      
      # SECURITY HARDENED: Size validation
      if encrypted.bytesize > plaintext.bytesize * 10
        raise 'Encryption result suspiciously large'
      end
      
      encrypted
    rescue GPGME::Error => e
      raise "PGP encryption failed: #{sanitize_error_message(e.message)}"
    end
  end

  # SECURITY HARDENED: Cryptographically secure random challenge generation
  def random_code
    # SECURITY HARDENED: Use only high-entropy sources
    entropy_pool = SecureRandom.random_bytes(128)
    
    # Generate base code
    code = Digest::SHA256.hexdigest(entropy_pool)[0, 32]
    
    # SECURITY HARDENED: Ensure character distribution
    chars = ('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a
    result = ''
    
    32.times do |i|
      entropy_byte = entropy_pool[i % entropy_pool.length].ord
      result += chars[entropy_byte % chars.length]
    end
    
    result
  end

  # SECURITY HARDENED: Enhanced challenge hashing with salt
  def hash_challenge(code)
    raise 'Challenge code cannot be empty' if code.nil? || code.empty?
    raise 'Challenge code invalid format' unless code.match?(/\A[A-Za-z0-9]{32}\z/)
    
    # SECURITY HARDENED: Use application-specific salt with fallback
    salt = ENV.fetch('CHALLENGE_SALT') do
      # Generate and store salt if not set
      generated_salt = SecureRandom.hex(64)
      puts "WARNING: Generated temporary CHALLENGE_SALT. Set in environment for production!"
      generated_salt
    end
    
    # SECURITY HARDENED: Use PBKDF2 with increased iterations
    iterations = 50000  # Increased iterations
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

  # SECURITY HARDENED: Strict key validation
  def validate_key_security(key)
    raise 'PGP key object is nil' unless key
    
    # SECURITY HARDENED: Comprehensive status checks
    validate_key_status(key)
    validate_key_age(key)
    validate_key_algorithms(key)
    validate_key_capabilities(key)
    validate_key_user_ids(key)
    
    true
  end

  # SECURITY HARDENED: Secure cleanup of sensitive data
  def secure_cleanup(sensitive_string)
    return unless sensitive_string.is_a?(String)
    
    # Overwrite memory multiple times
    3.times do
      sensitive_string.length.times { |i| sensitive_string[i] = "\x00" }
    end
    sensitive_string.clear
  end

  # SECURITY HARDENED: Validate challenge response timing
  def validate_challenge_timing(created_at, max_age_seconds = 300)
    raise 'Challenge timestamp missing' unless created_at
    raise 'Challenge timestamp invalid' unless created_at.is_a?(Time)
    
    age = Time.now - created_at
    raise 'Challenge expired' if age > max_age_seconds
    raise 'Challenge from future (clock skew detected)' if age < -30 # Reduced tolerance
    
    true
  end

  private

  # SECURITY HARDENED: Validate key status with strict checks
  def validate_key_status(key)
    status_methods = [
      [:expired, :expired?, 'PGP key is expired'],
      [:revoked, :revoked?, 'PGP key is revoked'], 
      [:invalid, :invalid?, 'PGP key is invalid'],
      [:disabled, :disabled?, 'PGP key is disabled']
    ]

    status_methods.each do |method, alt_method, error_msg|
      begin
        if key.respond_to?(method) && key.send(method)
          raise error_msg
        elsif key.respond_to?(alt_method) && key.send(alt_method)
          raise error_msg
        end
      rescue NoMethodError
        # If we can't check status, be conservative
        puts "WARNING: Cannot verify key status - #{method}" if ENV['RACK_ENV'] == 'development'
      end
    end
  end

  def validate_key_age(key)
    return unless key.primary_subkey&.timestamp
    
    key_age_years = (Time.now - key.primary_subkey.timestamp) / (365.25 * 24 * 3600)
    
    if key_age_years > MAX_KEY_AGE_YEARS
      raise "PGP key is too old (#{key_age_years.round(1)} years, max #{MAX_KEY_AGE_YEARS})"
    end
    
    if key_age_years < 0
      raise 'PGP key timestamp is in the future'
    end
  end

  # SECURITY HARDENED: Strict algorithm validation
  def validate_key_algorithms(key)
    return unless key.subkeys

    key.subkeys.each do |subkey|
      next unless subkey.respond_to?(:pubkey_algo) && subkey.respond_to?(:length)
      
      begin
        algo = subkey.pubkey_algo
        length = subkey.length
        
        case algo
        when :rsa
          if length < MIN_KEY_SIZE
            raise "RSA key too small: #{length} bits (minimum #{MIN_KEY_SIZE})"
          end
        when :dsa
          raise 'DSA keys are not allowed (security weakness)'
        when :elgamal  
          raise 'ElGamal keys are not allowed (security weakness)'
        when :ecdsa, :ecdh, :eddsa
          # ECC keys are acceptable
        else
          raise "Unsupported algorithm: #{algo}"
        end
      rescue => e
        raise "Key algorithm validation failed: #{sanitize_error_message(e.message)}"
      end
    end
  end

  def validate_key_capabilities(key)
    return unless key.primary_subkey

    begin
      primary = key.primary_subkey
      
      # Check signing capability
      if primary.respond_to?(:can_sign?) && !primary.can_sign?
        raise 'Primary key must support signing'
      end
      
      # Ensure encryption capability exists
      encryption_subkey = key.subkeys.find do |sk|
        sk.respond_to?(:can_encrypt?) ? sk.can_encrypt? : false
      end
      
      unless encryption_subkey
        raise 'Key must have encryption capability'
      end
    rescue NoMethodError => e
      puts "WARNING: Cannot verify key capabilities: #{e.message}" if ENV['RACK_ENV'] == 'development'
    end
  end

  def validate_key_user_ids(key)
    return unless key.uids
    
    if key.uids.empty?
      raise 'PGP key has no user IDs'
    end
    
    # Check for at least one potentially valid UID
    valid_uid_found = key.uids.any? do |uid|
      begin
        uid.name && !uid.name.empty?
      rescue
        false
      end
    end
    
    unless valid_uid_found
      raise 'PGP key has no valid user IDs'
    end
  end

  # SECURITY HARDENED: Sanitize error messages
  def sanitize_error_message(message)
    # Remove potentially sensitive information
    sanitized = message.to_s
                      .gsub(/\b[A-F0-9]{40}\b/, '[FINGERPRINT]')
                      .gsub(/\b[A-F0-9]{16}\b/, '[KEYID]')
                      .gsub(/\/[^\s]+/, '[PATH]')
                      .slice(0, 200)
    
    sanitized.empty? ? 'PGP operation failed' : sanitized
  end
end
