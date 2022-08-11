# frozen_string_literal: true

require_relative "ccipher_factory/version"

#require 'tlogger'
require 'teLogger'
require 'toolrack'

include TeLogger

require 'ccrypto'
require 'binenc'
if TR::RTUtils.on_jruby?
  require 'ccrypto/java'
  require 'binenc/java'
else
  require 'ccrypto/ruby'
  require 'binenc/ruby'
end

require_relative 'ccipher_factory/encoding/binenc_constant'
require_relative 'ccipher_factory/encoding/bin_struct'

require_relative 'ccipher_factory/encoding/asn1'

require_relative 'ccipher_factory/helpers/common'

require_relative 'ccipher_factory/digest/supported_digest'
require_relative 'ccipher_factory/digest/digest'
require_relative 'ccipher_factory/compression/compressor'
require_relative 'ccipher_factory/kcv/kcv'

require_relative 'ccipher_factory/symkey/symkey_generator'
require_relative 'ccipher_factory/symkey_cipher/symkey_cipher'
require_relative 'ccipher_factory/symkey_cipher/symkey_signer'

require_relative 'ccipher_factory/asymkey/asymkey_generator'
require_relative 'ccipher_factory/asymkey_cipher/asymkey_cipher'
require_relative 'ccipher_factory/asymkey_cipher/asymkey_signer'

require_relative 'ccipher_factory/composite_cipher/composite_cipher'

module CcipherFactory
  class Error < StandardError; end
  # Your code goes here...
  class SymKeyCipherError < StandardError; end
  class SymKeyDecryptionError < StandardError; end

end

MemBuf = Ccrypto::UtilFactory.instance(:membuf)

