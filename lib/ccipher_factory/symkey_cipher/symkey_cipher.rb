

require_relative 'symkey_encrypt'
require_relative 'symkey_decrypt'

require_relative 'symkey_att_encrypt'
require_relative 'symkey_att_decrypt'

module CcipherFactory
  module SymKeyCipher
    include TR::CondUtils

    class SKCipher; end

    #class SymKeyCipherError < StandardError; end

    def self.encryptor
      c = SKCipher.new
      c.extend(SymKeyEncrypt)
      c  
    end

    def self.decryptor
      dec = SKCipher.new
      dec.extend(SymKeyDecrypt)
      dec
    end

    def self.att_encryptor
      c = SKCipher.new
      c.extend(SymKeyAttEncrypt)
      c
    end

    def self.att_decryptor
      c = SKCipher.new
      c.extend(SymKeyAttDecrypt)
      c
    end

    #def self.mode_to_spec(mode)
    #  if not_empty?(mode)
    #    mode.to_s.upcase
    #  else
    #    mode
    #  end
    #end

    #def self.key_to_spec(key, mode)
    #  if not_empty?(key)
    #    case key.keytype
    #    when :aes
    #      "AES-#{key.keysize}-#{mode_to_spec(mode)}"
    #    when :chacha20_poly1305, :chacha20
    #      "chacha20-poly1305"
    #    when :blowfish
    #      "bf-#{mode_to_spec(mode)}"
    #    when :camellia
    #      "camellia-#{key.keysize}-#{mode_to_spec(mode)}"
    #    when :aria
    #      "aria-#{key.keysize}-#{mode_to_spec(mode)}"
    #    else
    #      raise SymKeyCipherError, "Unknown key type '#{key.keytype}'"
    #    end
    #  else
    #    raise SymKeyCipherError, "Given key to translate to spec is nil"
    #  end
    #end

    #def self.iv_length(key, mode)
    #  c = OpenSSL::Cipher.new(key_to_spec(key, mode))
    #  c.random_iv.length
    #end

    def SymKeyCipher.algo_default(algo)
      case algo
      when :aes
        # param 0: Algo name for spec
        # param 1: key size
        # param 2: default mdoe
        #["AES", 256, :gcm]
        Ccrypto::DirectCipherConfig.new({ algo: :aes, keysize: 256, mode: :gcm, padding: :pkcs5 })
      when :chacha20_poly1305, :chacha20
        Ccrypto::DirectCipherConfig.new({ algo: :chacha20, keysize: 256, mode: :poly1305 })
        #["chacha20-poly1305", 256]
      when :blowfish
        Ccrypto::DirectCipherConfig.new({ algo: :blowfish, keysize: 128, mode: :cfb, padding: :pkcs5 })
        #["bf", 128, :ofb]
      when :camellia
        Ccrypto::DirectCipherConfig.new({ algo: :camellia, keysize: 256, mode: :ctr, padding: :pkcs5 })
        #["camellia", 256, :ctr]
      when :aria
        Ccrypto::DirectCipherConfig.new({ algo: :aria, keysize: 256, mode: :gcm, padding: :pkcs5 })
        #["aria", 256, :gcm]
      else
        raise SymKeyCipherError, "Unknown algo '#{algo}' default"
      end
    end

  end
end
