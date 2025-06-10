# frozen_string_literal: true

# Production security configuration

# Ensure all required environment variables are set
required_vars = %w[DATABASE_URL SESSION_SECRET]
missing = required_vars.reject { |var| ENV[var] }

unless missing.empty?
  puts "❌ Missing required environment variables: #{missing.join(', ')}"
  exit 1
end

# Optionally set trusted proxy IP for accurate client IP detection
# ENV['TRUSTED_PROXY_IP'] = '10.0.0.1/32'  # Your load balancer IP

# Additional production settings
DB.extension :connection_validator
DB.pool.connection_validation_timeout = -1
