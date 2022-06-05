

RSpec.describe CcipherFactory::CompositeCipher do

  it 'signs with asymkey and encrypt with symkey of given input' do

    data = File.read(__FILE__)

    CcipherFactory::SymKeyGenerator.supported_symkey.each do |k,v|
    
      v[0].each do |ks|

        puts "Composite 1 with symkey #{k} or #{ks}"
        sk = CcipherFactory::SymKeyGenerator.generate(k, ks)
        ask = CcipherFactory::AsymKeyGenerator.generate(:ecc)

        cc = subject.sign_encryptor
        out = MemBuf.new
        cc.output(out)
        cc.signing_key = ask
        cc.encryption_key = sk
        cc.compression_on

        cc.sign_encrypt_init
        cc.sign_encrypt_update(data)
        meta = cc.sign_encrypt_final

        cv = subject.decrypt_verifier
        dout = MemBuf.new
        cv.output(dout)
        cv.decryption_key = sk

        cv.decrypt_verify_init
        cv.decrypt_verify_update_meta(meta)
        cv.decrypt_verify_update_cipher(out.bytes)
        res = cv.decrypt_verify_final

        p res
        expect(res).to be true
        expect(dout.equals?(data)).to be true
        #expect(cv.embedded_signer.to_der == ask.public_key.public_key.to_der).to be true
        expect(ask.is_public_key_equal?(cv.embedded_signer)).to be true

      end
    end
  end

  it 'signs with symkey and encrypt with asymkey of given input' do

    data = File.read(__FILE__)

    CcipherFactory::SymKeyGenerator.supported_symkey.each do |k,v|

      v[0].each do |ks|

        puts "Composite 2 with symkey #{k} or #{ks}"

        sk = CcipherFactory::SymKeyGenerator.generate(k, ks)
        ask = CcipherFactory::AsymKeyGenerator.generate(:ecc)

        cc = subject.sign_encryptor
        out = MemBuf.new
        cc.output(out)
        cc.signing_key = sk
        cc.encryption_key = ask.public_key
        cc.sender_keypair = ask
        cc.compression_on

        cc.sign_encrypt_init
        cc.sign_encrypt_update(data)
        meta = cc.sign_encrypt_final

        cv = subject.decrypt_verifier
        dout = MemBuf.new
        cv.output(dout)
        cv.decryption_key = ask
        cv.verification_key = sk

        cv.decrypt_verify_init
        cv.decrypt_verify_update_meta(meta)
        cv.decrypt_verify_update_cipher(out.bytes)
        res = cv.decrypt_verify_final   

        p res
        expect(res).to be true
        expect(dout.equals?(data)).to be true
      end
    end
    
  end


  it 'signs with asymkey and encrypt with asymkey too of given input' do

    data = File.read(__FILE__)

    ssk = CcipherFactory::AsymKeyGenerator.generate(:ecc)
    esk = CcipherFactory::AsymKeyGenerator.generate(:ecc)

    cc = subject.sign_encryptor
    out = MemBuf.new
    cc.output(out)
    cc.signing_key = ssk
    cc.sender_keypair = ssk
    cc.encryption_key = esk.public_key
    cc.compression_on

    cc.sign_encrypt_init
    cc.sign_encrypt_update(data)
    meta = cc.sign_encrypt_final

    cv = subject.decrypt_verifier
    dout = MemBuf.new
    cv.output(dout)
    cv.decryption_key = esk

    cv.decrypt_verify_init
    cv.decrypt_verify_update_meta(meta)
    cv.decrypt_verify_update_cipher(out.bytes)
    res = cv.decrypt_verify_final

    p res
    expect(res).to be true
    expect(dout.equals?(data)).to be true
    #expect(cv.embedded_signer.to_der == ssk.public_key.public_key.to_der).to be true
    expect(ssk.is_public_key_equal?(cv.embedded_signer)).to be true
    
  end


  it 'signs with symkey and encrypt with symkey too of given input' do

    data = File.read(__FILE__)

    CcipherFactory::SymKeyGenerator.supported_symkey.each do |k,v|

      v[0].each do |ks|

        puts "Composite 3 with symkey #{k} or #{ks}"
        ssk = CcipherFactory::SymKeyGenerator.generate(k,ks)
        esk = CcipherFactory::SymKeyGenerator.generate(k,ks)

        cc = subject.sign_encryptor
        out = MemBuf.new
        cc.output(out)
        cc.signing_key = ssk
        cc.encryption_key = esk
        cc.compression_on

        cc.sign_encrypt_init
        cc.sign_encrypt_update(data)
        meta = cc.sign_encrypt_final

        cv = subject.decrypt_verifier
        dout = MemBuf.new
        cv.output(dout)
        cv.decryption_key = esk
        cv.verification_key = ssk

        cv.decrypt_verify_init
        cv.decrypt_verify_update_meta(meta)
        cv.decrypt_verify_update_cipher(out.bytes)
        res = cv.decrypt_verify_final

        p res
        expect(res).to be true
        expect(dout.equals?(data)).to be true

      end
    end
    
  end

end
