
require_relative '../../digest/digest'
require_relative '../../compression/compressor'

module CcipherFactory
  module AsymKeySigner
    module ECCSigner
      include TR::CondUtils
      include Common

      class ECCSignerError < AsymKeySignerError; end

      attr_accessor :signing_key

      def compression_on
        @compress = true
      end

      def compression_off
        @compress = false
      end

      def sign_init(opts = {  }, &block)

        raise ECCSignerError, "Signer must be given" if is_empty?(@signing_key)

        @digest = Digest.instance
        @digest.output(intOutputBuf)
        @digest.digest_init

        if @compress
          logger.tdebug :asymkey_enc, "Compression on"
          @compressor = CcipherFactory::Compression::Compressor.new 
          @compressor.compress
          @compressor.compress_init
        else
          logger.tdebug :asymkey_enc, "Compression off"
        end


        if block
          instance_eval(&block)
          sign_final
        else
          self
        end

      end

      def sign_update(val)
        @digest.digest_update(val)
      end

      def sign_final
        dig = @digest.digest_final

        eccConf = Ccrypto::ECCConfig.new
        eccConf.keypair = @signing_key.keypair
        eccEng = Ccrypto::AlgoFactory.engine(eccConf)
        sign = eccEng.sign(intOutputBuf.string)

        #sign = @signing_key.dsa_sign_asn1(intOutputBuf.string)

        ts = Encoding::ASN1Encoder.instance(:ecc_signature)
        ts.set(:digest_info, dig)
        # todo strengthen this with x.509 certificate?
        # Or put certificate outside of envelope?
        ts.set(:signer_info, @signing_key.to_signer_info)
        ts.set(:signature, sign)
        ts.to_asn1

      end

      def logger
        if @logger.nil?
          @logger = Tlogger.new
        end
        @logger
      end


    end
  end
end
