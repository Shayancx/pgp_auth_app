# -*- encoding: utf-8 -*-
# stub: rodauth 2.39.0 ruby lib

Gem::Specification.new do |s|
  s.name = "rodauth".freeze
  s.version = "2.39.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/jeremyevans/rodauth/issues", "changelog_uri" => "https://rodauth.jeremyevans.net/rdoc/files/CHANGELOG.html", "documentation_uri" => "https://rodauth.jeremyevans.net/documentation.html", "mailing_list_uri" => "https://github.com/jeremyevans/rodauth/discussions", "source_code_uri" => "https://github.com/jeremyevans/rodauth" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Jeremy Evans".freeze]
  s.date = "1980-01-02"
  s.description = "Rodauth is Ruby's most advanced authentication framework, designed\nto work in all rack applications.  It's built using Roda and Sequel,\nbut it can be used as middleware in front of web applications that use\nother web frameworks and database libraries.\n\nRodauth aims to provide strong security for password storage by\nutilizing separate database accounts if possible on PostgreSQL,\nMySQL, and Microsoft SQL Server.  Configuration is done via\na DSL that makes it easy to override any part of the authentication\nprocess.\n\nRodauth supports typical authentication features: such as login and\nlogout, changing logins and passwords, and creating, verifying,\nunlocking, and resetting passwords for accounts.  Rodauth also\nsupports many advanced authentication features:\n\n* Secure password storage using security definer database functions\n* Multiple primary multifactor authentication methods (WebAuthn and\n  TOTP), as well as backup multifactor authentication methods (SMS\n  and recovery codes).\n* Passwordless authentication using email links and WebAuthn\n  authenticators.\n* Both standard HTML form and JSON API support for all features.\n".freeze
  s.email = "code@jeremyevans.net".freeze
  s.extra_rdoc_files = ["MIT-LICENSE".freeze]
  s.files = ["MIT-LICENSE".freeze]
  s.homepage = "https://rodauth.jeremyevans.net".freeze
  s.licenses = ["MIT".freeze]
  s.rdoc_options = ["--quiet".freeze, "--line-numbers".freeze, "--inline-source".freeze, "--title".freeze, "Rodauth: Ruby's Most Advanced Authentication Framework".freeze, "--main".freeze, "README.rdoc".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.9.2".freeze)
  s.rubygems_version = "3.6.7".freeze
  s.summary = "Authentication and Account Management Framework for Rack Applications".freeze

  s.installed_by_version = "3.6.7".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<sequel>.freeze, [">= 4".freeze])
  s.add_runtime_dependency(%q<roda>.freeze, [">= 2.6.0".freeze])
  s.add_development_dependency(%q<tilt>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rack_csrf>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<bcrypt>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<argon2>.freeze, [">= 2".freeze])
  s.add_development_dependency(%q<mail>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rotp>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rqrcode>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<jwt>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<webauthn>.freeze, [">= 2".freeze])
  s.add_development_dependency(%q<minitest>.freeze, [">= 5.0.0".freeze])
  s.add_development_dependency(%q<minitest-global_expectations>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<minitest-hooks>.freeze, [">= 1.1.0".freeze])
  s.add_development_dependency(%q<capybara>.freeze, [">= 2.1.0".freeze])
end
