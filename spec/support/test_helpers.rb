# frozen_string_literal: true

# Helper methods for tests
module TestHelpers
  def generate_pgp_keypair
    GPGME::Key.create(
      name: 'Test User',
      email: 'test@example.com',
      expires_in: '1y'
    )
  end

  def import_test_key
    key_text = File.read('spec/fixtures/test_public_key.asc')
    GPGME::Key.import(key_text)
    key_text
  end

  def decrypt_challenge(encrypted_text)
    crypto = GPGME::Crypto.new
    crypto.decrypt(encrypted_text).to_s.strip
  end

  def login_as(account)
    post '/login', username: account[:username]
    post '/login-password', password: 'password123'

    get '/pgp-2fa'
    encrypted = last_response.body.match(%r{<pre class="encrypted-text">(.*?)</pre>}m)[1]
    code = decrypt_challenge(CGI.unescapeHTML(encrypted))
    post '/pgp-2fa', code: code
  end
end
