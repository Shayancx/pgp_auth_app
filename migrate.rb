#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative 'config/database'
require 'sequel'

Sequel.extension :migration
puts 'Running migrations...'
Sequel::Migrator.run(DB, 'db/migrate')
puts 'Migrations completed'
