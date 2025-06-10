# frozen_string_literal: true

# Environment validation for security
class EnvironmentValidator
  REQUIRED_VARS = %w[
    DATABASE_URL
    SESSION_SECRET
  ].freeze

  PRODUCTION_VARS = %w[
    TRUSTED_PROXY_IP
    SESSION_DOMAIN
    CHALLENGE_SALT
    SESSION_SALT
    RATE_LIMIT_SALT
  ].freeze

  class << self
    def validate!
      validate_required_vars
      validate_production_vars if ENV['RACK_ENV'] == 'production'
      validate_secret_strength
      validate_database_connection
      
      puts "✅ Environment validation passed"
    end

    private

    def validate_required_vars
      missing = REQUIRED_VARS.reject { |var| ENV[var] }
      
      unless missing.empty?
        puts "❌ Missing required environment variables: #{missing.join(', ')}"
        exit 1
      end
    end

    def validate_production_vars
      if ENV['RACK_ENV'] == 'production'
        missing = PRODUCTION_VARS.reject { |var| ENV[var] }
        
        unless missing.empty?
          puts "⚠️  Missing recommended production variables: #{missing.join(', ')}"
          puts "   Application will use defaults, but this is not recommended for production"
        end
      end
    end

    def validate_secret_strength
      session_secret = ENV['SESSION_SECRET']
      
      if session_secret.length < 64
        puts "❌ SESSION_SECRET must be at least 64 characters"
        exit 1
      end
      
      # Check entropy
      entropy = calculate_entropy(session_secret)
      if entropy < 4.0
        puts "❌ SESSION_SECRET has insufficient entropy (#{entropy.round(2)})"
        exit 1
      end
    end

    def validate_database_connection
      require_relative '../config/database'
      
      begin
        DB.test_connection
      rescue => e
        puts "❌ Database connection failed: #{e.message}"
        exit 1
      end
    end

    def calculate_entropy(string)
      chars = string.chars
      frequencies = chars.group_by(&:itself).transform_values(&:count)
      
      entropy = 0
      frequencies.each do |_, count|
        probability = count.to_f / chars.length
        entropy -= probability * Math.log2(probability)
      end
      
      entropy
    end
  end
end
