# frozen_string_literal: true

require_relative '../config/database'
require 'securerandom'
require 'json'
require_relative 'session_manager/session_operations'
require_relative 'session_manager/revocation'
require_relative 'session_manager/audit_logger'
require_relative 'session_manager/maintenance'

# Main module for session management functionality
module SessionManager
  extend SessionOperations
  extend Revocation
  extend AuditLogger
  extend Maintenance
end
