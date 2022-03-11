

module CcipherFactory
  module CompositeCipher

    class CompositeCipherError < StandardError; end

    class CompCipher; end

    def self.sign_encryptor(opts = {  })
      cc = CompCipher.new
      cc.extend(SignEncryptor)
      cc
    end

    def self.decrypt_verifier(opts = {  })
      cc = CompCipher.new
      cc.extend(DecryptVerifier)
      cc
    end

  end
end

require_relative 'sign_encryptor'
require_relative 'decrypt_verifier'


