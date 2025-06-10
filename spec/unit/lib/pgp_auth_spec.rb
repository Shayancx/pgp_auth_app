require 'spec_helper'

RSpec.describe PgpAuth do
  before(:all) do
    # Import test key for all tests
    @test_key = File.read('spec/fixtures/test_public_key.asc')
    @fingerprint = GPGME::Key.import(@test_key).imports.first.fingerprint
  end

  describe '.import_and_fingerprint' do
    it 'imports a valid PGP key and returns fingerprint' do
      fingerprint = PgpAuth.import_and_fingerprint(@test_key)
      expect(fingerprint).to match(/^[A-F0-9]{40}$/i)
    end

    it 'raises error for invalid PGP key' do
      expect {
        PgpAuth.import_and_fingerprint("invalid key data")
      }.to raise_error(GPGME::Error)
    end

    it 'handles empty input' do
      expect {
        PgpAuth.import_and_fingerprint("")
      }.to raise_error(GPGME::Error)
    end
  end

  describe '.encrypt_for' do
    it 'encrypts plaintext for given fingerprint' do
      plaintext = "test message"
      encrypted = PgpAuth.encrypt_for(@fingerprint, plaintext)
      
      expect(encrypted).to include("-----BEGIN PGP MESSAGE-----")
      expect(encrypted).to include("-----END PGP MESSAGE-----")
    end

    it 'raises error for non-existent fingerprint' do
      expect {
        PgpAuth.encrypt_for("NONEXISTENT0000000000000000000000000000", "test")
      }.to raise_error(/public key .* not found/)
    end

    it 'encrypts different messages differently' do
      encrypted1 = PgpAuth.encrypt_for(@fingerprint, "message1")
      encrypted2 = PgpAuth.encrypt_for(@fingerprint, "message2")
      
      expect(encrypted1).not_to eq(encrypted2)
    end
  end

  describe '.random_code' do
    it 'generates 32-character alphanumeric code' do
      code = PgpAuth.random_code
      expect(code).to match(/^[a-zA-Z0-9]{32}$/)
    end

    it 'generates unique codes' do
      codes = Array.new(100) { PgpAuth.random_code }
      expect(codes.uniq.size).to eq(100)
    end
  end
end
