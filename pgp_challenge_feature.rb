# frozen_string_literal: true
require_relative "lib/pgp_auth"

Rodauth.create_feature(:pgp_challenge) do
  depends :logout               # keep session handling

  auth_value_method :challenge_ttl, 300 # 5 min

  route do |r|
    r.on "pgp-auth" do
      rodauth.require_account # redirected from /register

      # STEP 1 – show encrypted challenge
      r.get do
        code   = PgpAuth.random_code
        DB[:challenges].insert(account_id: account_id,
                               code: code,
                               expires_at: Time.now + challenge_ttl)
        @encrypted = PgpAuth.encrypt_for(account[:fingerprint], code)
        view("show_encrypted")
      end

      # STEP 2 – user submits plaintext
      r.post do
        row = DB[:challenges].where(account_id: account_id)
                              .reverse(:id).first
        r.redirect "/pgp-auth?expired=1" unless row &&
                                               row[:expires_at] > Time.now
        if r.params["code"] == row[:code]
          DB[:challenges].where(id: row[:id]).delete
          session[session_key] = account_id
          r.redirect "/dashboard"
        else
          r.redirect "/pgp-auth?fail=1"
        end
      end
    end
  end
end
