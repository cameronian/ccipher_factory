
require 'openssl'
require 'securerandom'

require_relative 'soft_symkey'
require_relative 'derived_symkey'

module CcipherFactory
  module SymKeyGenerator
    include TR::CondUtils

    class SymKeyGeneratorError < StandardError; end

    def self.supported_symkey
      { aes: [[128, 256], [:gcm, :cbc, :cfb, :ctr, :ofb]], 
        chacha20: [[256],[:poly1305]], 
        blowfish: [[128],[:cbc, :cfb, :ecb, :ofb]],
        camellia: [[128,192,256],[:cbc, :cfb, :ctr, :ecb, :ofb]],
        aria: [[128,192,256],[:cbc, :cfb, :ctr, :ecb, :gcm, :ofb]]
      }
    end

    def self.generate(keytype, keysize, *args, &block)
      raise SymKeyGeneratorError, "Unsupported symmetric key algo '#{keytype}'. Supported symmetric keys are: #{supported_symkey.keys.join(", ")}" if not supported_symkey.keys.include?(keytype)

      SoftSymKey.new(keytype, keysize, SecureRandom.random_bytes(keysize/8))
    end

    def self.derive(keytype, keysize, *args, &block)
      raise SymKeyGeneratorError, "Unsupported symmetric key algo '#{keytype}'. Supported symmetric keys are: #{supported_symkey.keys.join(", ")}" if not supported_symkey.keys.include?(keytype)

      raise SymKeyGeneratorError, "Block is required" if not block

      kdf = block.call(:kdf)
      kdf = :scrypt if is_empty?(kdf)

      pass = block.call(:password)
      raise SymKeyGeneratorError, "Password is not given to derive the symkey" if is_empty?(pass)

      dsk = DerivedSymKey.new(keytype, keysize) 
      dsk.derive(pass, kdf)
      dsk
    end

  end
end
