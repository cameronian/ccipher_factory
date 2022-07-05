
require 'openssl'
require 'securerandom'

require_relative 'soft_symkey'
require_relative 'derived_symkey'

module CcipherFactory
  module SymKeyGenerator
    include TR::CondUtils

    class SymKeyGeneratorError < StandardError; end

    def self.supported_symkey
      #{ 
      #  aes: [[128, 256], [:cbc, :cfb, :ctr, :ofb, :gcm]], 
      #  chacha20: [[256],[:poly1305]], 
      #  blowfish: [[128],[:ecb, :cbc, :cfb, :ofb]],
      #  camellia: [[128,192,256],[:ecb, :cbc, :cfb, :ofb, :ctr]],
      #  aria: [[128,192,256],[:ecb, :cbc, :cfb, :ofb, :ctr, :gcm]]
      #}
      { 
        aes: { keysize: [128, 192, 256], mode: [:cbc, :cfb, :ctr, :ofb, :gcm] }, 
        chacha20: { keysize: [256], mode: [:poly1305] }, 
        blowfish: { keysize: [128], mode: [:ecb, :cbc, :cfb, :ofb] },
        camellia: { keysize: [128, 192, 256], mode: [:ecb, :cbc, :cfb, :ofb, :ctr] },
        aria: { keysize: [128, 192, 256], mode: [:ecb, :cbc, :cfb, :ofb, :ctr, :gcm] }
      }.freeze

    end

    def self.generate(keytype, keysize, *args, &block)
      raise SymKeyGeneratorError, "Unsupported symmetric key algo '#{keytype}'. Supported symmetric keys are: #{supported_symkey.keys.join(", ")}" if not supported_symkey.keys.include?(keytype)

      kc = Ccrypto::KeyConfig.new
      kc.algo = keytype
      kc.keysize = keysize
      ke = Ccrypto::AlgoFactory.engine(Ccrypto::KeyConfig)
      sk = ke.generate(kc)

      #SoftSymKey.new(keytype, keysize, SecureRandom.random_bytes(keysize/8))
      SoftSymKey.new(keytype, keysize, sk)
    end

    def self.derive(keytype, keysize, *args, &block)
      raise SymKeyGeneratorError, "Unsupported symmetric key algo '#{keytype}'. Supported symmetric keys are: #{supported_symkey.keys.join(", ")}" if not supported_symkey.keys.include?(keytype)

      raise SymKeyGeneratorError, "Block is required" if not block

      kdf = block.call(:kdf)
      kdf = :scrypt if is_empty?(kdf)

      pass = block.call(:password)
      raise SymKeyGeneratorError, "Password is not given to derive the symkey" if is_empty?(pass)

      dsk = DerivedSymKey.new(keytype, keysize) 
      dsk.derive(pass, kdf, &block)
      dsk
    end

    def self.logger
      if @logger.nil?
        @logger = Tlogger.new
        @logger.tag = :symkey_gen
      end
      @logger
    end

  end
end
