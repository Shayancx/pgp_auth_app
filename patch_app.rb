#!/usr/bin/env ruby
# frozen_string_literal: true

# This script patches app.rb to ensure zero-knowledge security

content = File.read('app.rb')

# Patch 1: Update generate_pgp_challenge to use hashed codes
content.gsub!(/(def generate_pgp_challenge.*?)(code = PgpAuth\.random_code)(.*?)(DB\[:challenges\]\.insert\()(.*?)(code: code,)(.*?end)/m) do |_match|
  pre = Regexp.last_match(1)
  gen_code = Regexp.last_match(2)
  mid1 = Regexp.last_match(3)
  insert = Regexp.last_match(4)
  mid2 = Regexp.last_match(5)
  Regexp.last_match(6)
  rest = Regexp.last_match(7)

  <<~RUBY
    #{pre}#{gen_code}
        code_hash = PgpAuth.hash_challenge(code)#{mid1}#{insert}#{mid2}code_hash: code_hash,#{rest}
  RUBY
end

# Patch 2: Update verify_pgp_challenge to use hashed codes
content.gsub!(/(def verify_pgp_challenge.*?)(submitted_code == row\[:code\])/m) do |_match|
  pre = Regexp.last_match(1)
  Regexp.last_match(2)

  <<~RUBY
    #{pre}submitted_hash = PgpAuth.hash_challenge(submitted_code)
        secure_compare(submitted_hash, row[:code_hash])
  RUBY
end

# Patch 3: Update verify-pgp route to hash verification codes
content.gsub!(/(verification_code: code,)/m, 'verification_code: code_hash,')
content.gsub!(/(code = PgpAuth\.random_code)\s*\n\s*(DB\[:accounts\]\.where)/m) do |_match|
  "code = PgpAuth.random_code\n          code_hash = PgpAuth.hash_challenge(code)\n          \n          DB[:accounts].where"
end

# Patch 4: Fix verification check
content.gsub!(/(if submitted_code == account\[:verification_code\])/m) do |_match|
  <<~RUBY
    submitted_hash = PgpAuth.hash_challenge(submitted_code)
    #{'        '}
            if secure_compare(submitted_hash, account[:verification_code])
  RUBY
end

# Write the patched content
File.write('app.rb', content)
puts '✓ app.rb patched for zero-knowledge security'
