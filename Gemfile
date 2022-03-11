# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in ccipher_factory.gemspec
gemspec

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

gem 'ccrypto',  git: 'ccrypto', branch: 'master'

require 'toolrack'
if defined?(TR::RTUtils)
  if TR::RTUtils.on_jruby?
    gem 'ccrypto-java', git: 'ccrypto-java', branch: 'master'
  else
    gem 'ccrypto-ruby', git: 'ccrypto-ruby', branch: 'master'
  end
end


