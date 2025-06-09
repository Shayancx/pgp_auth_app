# frozen_string_literal: true
require_relative "lib/pgp_auth"

module Rodauth
  Feature.define(:pgp_challenge) do
    depends :logout

    auth_value_method :challenge_ttl, 300 # 5 min

    route do |r|
      r.on "pgp-auth" do
        account_id = session[:account_id]
        r.redirect "/" unless account_id
        
        account = DB[:accounts].where(id: account_id).first
        r.redirect "/" unless account

        r.get do
          # Clean up expired challenges
          DB[:challenges].where(account_id: account_id)
                         .where { expires_at < Time.now }
                         .delete
          
          code = PgpAuth.random_code
          DB[:challenges].insert(account_id: account_id,
                                 code: code,
                                 expires_at: Time.now + challenge_ttl)
          @encrypted = PgpAuth.encrypt_for(account[:fingerprint], code)
          view("show_encrypted")
        end

        r.post do
          submitted_code = r.params["code"].to_s.strip
          
          # Rate limiting
          recent_attempts = DB[:challenges].where(account_id: account_id)
                                          .where { created_at > Time.now - 60 }
                                          .count
          
          if recent_attempts > 5
            flash["error"] = "Too many attempts. Please wait before trying again."
            r.redirect "/pgp-auth"
          end
          
          row = DB[:challenges].where(account_id: account_id)
                                .reverse(:id).first
                                
          unless row && row[:expires_at] > Time.now
            flash["error"] = "Challenge expired. Please try again."
            r.redirect "/pgp-auth"
          end
          
          if submitted_code == row[:code]
            DB[:challenges].where(account_id: account_id).delete
            session[session_key] = account_id
            session.delete(:account_id)
            flash["notice"] = "Successfully authenticated with PGP!"
            r.redirect "/dashboard"
          else
            flash["error"] = "Invalid code. Please try again."
            r.redirect "/pgp-auth"
          end
        end
      end
    end
  end
end
