#!/usr/bin/env ruby
# Cleanup script for old rate limit records
# Run this periodically via cron job

require_relative "config/database"
require_relative "lib/rate_limit"

puts "Cleaning up old rate limit records..."
deleted = RateLimit.cleanup_old_records
puts "Deleted #{deleted} old records"
