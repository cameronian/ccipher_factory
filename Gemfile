# frozen_string_literal: true

source "https://rubygems.org"

# Specify your gem's dependencies in ccipher_factory.gemspec
gemspec

gem "rake", "~> 13.0"

gem "rspec", "~> 3.0"

gem 'ccrypto',  git: 'ccrypto', branch: 'main'

gem 'binenc', git: "binenc", branch: "master"

#gem 'toolrack', git: "toolrack", branch: "master"
require 'toolrack'
#if defined?(TR::RTUtils)
  if TR::RTUtils.on_jruby?
    gem 'ccrypto-java', git: 'ccrypto-java', branch: 'main'
    gem 'binenc-java', git: 'binenc-java', branch: 'master'
  else
    gem 'ccrypto-ruby', git: 'ccrypto-ruby', branch: 'main'
    gem 'binenc-ruby', git: 'binenc-ruby', branch: 'master'
  end
#end



