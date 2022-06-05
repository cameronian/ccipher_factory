# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in ccipher_factory.gemspec
gemspec

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

gem 'ccrypto',  git: 'ccrypto', branch: 'main'

require 'toolrack'
if defined?(TR::RTUtils)
  if TR::RTUtils.on_jruby?
    gem 'ccrypto-java', git: 'ccrypto-java', branch: 'main'
  else
    gem 'ccrypto-ruby', git: 'ccrypto-ruby', branch: 'main'
  end
end

gem 'toolrack', git: "toolrack", branch: "master"


