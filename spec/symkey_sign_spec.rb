

RSpec.describe CcipherFactory::SymKeySigner do
 
  it 'signs and verifies given data' do
    
    data = "Message to be protected" 

    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)

    sign = subject.signer
    sign.signing_key = sk
    sign.sign_init
    sign.sign_update(data)
    meta = sign.sign_final

    ver = subject.verifier
    ver.verification_key = sk
    ver.verify_init
    ver.verify_update_meta(meta)
    ver.verify_update_data(data)
    res = ver.verify_final

    p res
    expect(res).to be true

    ver = subject.verifier
    ver.verification_key = sk
    ver.verify_init
    ver.verify_update_meta(meta)
    ver.verify_update_data("random data")
    res = ver.verify_final

    p res
    expect(res).to be false

  end

  it 'signs and verifies given data for all supported symkey algo' do
    
    CcipherFactory::SymKeyGenerator.supported_symkey.each do |k,v|

      v[0].each do |ks|

        puts "Symkey #{k}-#{ks}"

        data = SecureRandom.random_bytes(64)

        sk = CcipherFactory::SymKeyGenerator.generate(k,ks)

        sign = subject.signer
        sign.signing_key = sk
        sign.sign_init
        sign.sign_update(data)
        meta = sign.sign_final

        ver = subject.verifier
        ver.verification_key = sk
        ver.verify_init
        ver.verify_update_meta(meta)
        ver.verify_update_data(data)
        res = ver.verify_final

        expect(res).to be true

        if not @prevKey.nil?
          ver = subject.verifier
          ver.verification_key = @prevKey
          ver.verify_init
          ver.verify_update_meta(meta)
          ver.verify_update_data(data)
          res = ver.verify_final

          expect(res).to be false
        end

        @prevKey = sk

      end
    end

  end


end
