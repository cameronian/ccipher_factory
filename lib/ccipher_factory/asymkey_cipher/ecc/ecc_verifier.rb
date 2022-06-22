
require_relative '../../asymkey/ecc_keypair'

module CcipherFactory
  module AsymKeySigner
    module ECCVerifier
      include Common

      attr_accessor :verification_key
      attr_reader :embedded_signer 
      def verify_init(*args, &block)

        if block
          instance_eval(&block)
          verify_final
        else
          self
        end

      end

      def verify_update_meta(meta)

        ts = BinStruct.instance.struct_from_bin(meta)
        digInfo = ts.digest_info
        sigInfo = ts.signer_info
        @sign = ts.signature

        @digest = Digest.from_asn1(digInfo)
        @digest.output(intOutputBuf)

        @signer = KeyPair::ECCKeyPair.from_signer_info(sigInfo)
        @embedded_signer = @signer

      end

      def verify_update_data(data)
        @digest.digest_update(data) 
      end

      def verify_final

        @digest.digest_final
        
        res = Ccrypto::AlgoFactory.engine(Ccrypto::ECCConfig).verify(@signer, intOutputBuf.bytes, @sign)
        
        #res = @signer.dsa_verify_asn1(intOutputBuf.string, @sign)

        res

      end

    end
  end

end
