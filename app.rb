# frozen_string_literal: true
require "roda"
require_relative "config/database"
require "rodauth"
require_relative "pgp_challenge_feature"

class App < Roda
  plugin :render, escape: true
  plugin :flash
  plugin :sessions, secret: ENV.fetch("SESSION_SECRET") { "dev_secret_change_this_to_something_much_longer_at_least_64_chars_for_security" }
  plugin :csrf

  plugin :rodauth do
    enable :pgp_challenge
    login_redirect "/dashboard"
    logout_redirect "/"
  end

  route do |r|
    r.rodauth                       # Rodauth routes

    r.root { view("home") }

    r.on "register" do
      r.get { view("register") }

      r.post do
        key_text = r.params["public_key"].to_s.strip
        halt(400, "Public key required") if key_text.empty?
        fp = PgpAuth.import_and_fingerprint(key_text)
        id = DB[:accounts].insert(public_key: key_text, fingerprint: fp)
        session[:account_id] = id
        r.redirect "/pgp-auth"
      end
    end

    r.on "dashboard" do
      rodauth.require_authentication
      view("dashboard")
    end
  end
end