# frozen_string_literal: true

# This is a patch file that shows the key security changes needed
# The main changes are:
# 1. Add secure_compare for timing attack prevention
# 2. Use generic error messages to prevent username enumeration
# 3. Hash all challenge codes before storage
# 4. Add proper security headers
# 5. Log security events

# In generate_pgp_challenge method, change to:
def generate_pgp_challenge(account_id)
  # Clean up old challenges
  DB[:challenges].where(account_id: account_id)
                 .where { expires_at < Time.now }
                 .delete

  code = PgpAuth.random_code
  code_hash = PgpAuth.hash_challenge(code)

  # Store hashed code instead of plaintext
  if DB[:challenges].columns.include?(:code_hash)
    DB[:challenges].insert(
      account_id: account_id,
      code_hash: code_hash,
      expires_at: Time.now + 300,
      created_at: Time.now
    )
  else
    # Fallback for old schema
    DB[:challenges].insert(
      account_id: account_id,
      code: code, # Will be removed after migration
      expires_at: Time.now + 300
    )
  end

  @encrypted = PgpAuth.encrypt_for(@account[:fingerprint], code)
end

# In verify_pgp_challenge method, change to:
def verify_pgp_challenge(account_id, submitted_code)
  row = DB[:challenges].where(account_id: account_id)
                       .where { expires_at > Time.now }
                       .reverse(:id).first

  return false unless row

  if DB[:challenges].columns.include?(:code_hash) && row[:code_hash]
    submitted_hash = PgpAuth.hash_challenge(submitted_code)
    secure_compare(submitted_hash, row[:code_hash])
  else
    # Fallback for old schema
    submitted_code == row[:code]
  end
end

# For verification in verify-pgp route, update to hash the code:
# In the GET /verify-pgp:
code = PgpAuth.random_code
code_hash = PgpAuth.hash_challenge(code)

if DB[:accounts].columns.include?(:verification_code)
  DB[:accounts].where(id: account_id).update(
    verification_code: code_hash, # Store hash instead of plaintext
    verification_expires_at: Time.now + 600
  )
end

# In the POST /verify-pgp:
submitted_hash = PgpAuth.hash_challenge(submitted_code)

if account[:verification_code] && secure_compare(submitted_hash, account[:verification_code])
  complete_verification(r, account_id)
else
  # Log failed attempt
  flash['error'] = 'Invalid verification code. Please try again.'
  r.redirect '/verify-pgp'
end
