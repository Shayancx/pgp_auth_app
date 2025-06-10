# frozen_string_literal: true

require_relative 'lib/pgp_auth'

module Rodauth
  Feature.define(:pgp_challenge) do
    depends :base

    auth_value_method :challenge_ttl, 300 # 5 min

    # This feature only provides helper methods
  end
end
