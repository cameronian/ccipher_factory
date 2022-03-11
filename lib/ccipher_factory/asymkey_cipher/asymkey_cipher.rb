

module CcipherFactory
  module AsymKeyCipher
    include TR::CondUtils

    class ASKCipher; end

    class AsymKeyCipherError < StandardError; end

    def self.encryptor(eng = :ecc)
      c = ASKCipher.new
      case eng
      when :ecc
        c.extend(ECCEncrypt)
      else
        raise AsymKeyCipherError, "Not supported encryptor engine '#{eng}'"
      end
      c
    end

    def self.decryptor(eng = :ecc)
      c = ASKCipher.new
      case eng
      when :ecc
        c.extend(ECCDecrypt)
      else
        raise AsymKeyCipherError, "Not supoprted decryptor engine '#{eng}'"
      end
      c
    end

    def self.att_encryptor(eng = :ecc)
      c = ASKCipher.new
      case eng
      when :ecc
        c.extend(ECCAttEncrypt)
      else
        raise AsymKeyCipherError, "Not supported encryptor engine '#{eng}'"
      end
      c
    end

    def self.att_decryptor(eng = :ecc)
      c = ASKCipher.new
      case eng
      when :ecc
        c.extend(ECCAttDecrypt)
      else
        raise AsymKeyCipherError, "Not supoprted decryptor engine '#{eng}'"
      end
      c
    end

  end
end

require_relative 'ecc/ecc_encrypt'
require_relative 'ecc/ecc_decrypt'

require_relative 'ecc/ecc_att_encrypt'
require_relative 'ecc/ecc_att_decrypt'

