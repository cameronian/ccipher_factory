
require_relative '../lib/ccipher_factory/symkey/symkey_generator'
require_relative '../lib/ccipher_factory/symkey_cipher/symkey_cipher'

RSpec.describe CcipherFactory::SymKeyCipher do

  it 'performs attached encryption and decryption on softsymkey' do
   
    data = "Super secret data!"

    comp = Ccrypto::UtilFactory.instance(:comparator)

    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)
    c = subject.att_encryptor
    c.mode = :gcm
    encBuf = MemBuf.new
    c.output(encBuf)
    c.key = sk
    c.att_encrypt_init
    c.att_encrypt_update(data)
    c.att_encrypt_final

    sk.attach_mode
    skBin = sk.encoded

    expect(encBuf.bytes.length > 0).to be true

    rsk = CcipherFactory::SoftSymKey.from_encoded(skBin)
    rskc = CcipherFactory::SymKey.from_encoded(skBin)
    expect(comp.is_equals?(rsk.key, rskc.key)).to be true
    dc = subject.att_decryptor
    decBuf = MemBuf.new
    dc.output(decBuf)
    dc.key = rsk
    dc.att_decrypt_init
    dc.att_decrypt_update(encBuf.bytes)
    dc.att_decrypt_final

    expect(decBuf.equals?(data)).to be true

  end

  it 'performs attached encryption and decryption on softsymkey with compression on' do
   
    data = File.read("spec/symkey_cipher_spec.rb")
    puts "Input data size : #{data.length}"

    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)
    c = subject.att_encryptor
    encBuf = MemBuf.new
    c.output(encBuf)
    c.compression_on
    c.key = sk
    c.att_encrypt_init
    c.att_encrypt_update(data)
    c.att_encrypt_final

    sk.attach_mode
    skBin = sk.encoded

    expect(encBuf.bytes.length > 0).to be true

    File.open("att_enc.bin","wb") do |f|
      f.write encBuf.bytes
    end

    rsk = CcipherFactory::SoftSymKey.from_encoded(skBin)
    dc = subject.att_decryptor
    decBuf = MemBuf.new
    dc.output(decBuf)
    dc.key = rsk
    dc.att_decrypt_init
    dc.att_decrypt_update(encBuf.bytes)
    dc.att_decrypt_final

    expect(decBuf.equals?(data)).to be true

  end


  it 'performs attached encryption and decryption on derivedsymkey' do
   
    data = "Super secret data for password!"

    sk = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    c = subject.att_encryptor
    encBuf = MemBuf.new
    c.output(encBuf)
    c.key = sk
    c.att_encrypt_init
    c.att_encrypt_update(data)
    c.att_encrypt_final

    skBin = sk.encoded

    expect(encBuf.bytes.length > 0).to be true

    rsk = CcipherFactory::DerivedSymKey.from_encoded(skBin) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    dc = subject.att_decryptor
    decBuf = MemBuf.new
    dc.output(decBuf)
    dc.key = rsk
    dc.att_decrypt_init
    dc.att_decrypt_update(encBuf.bytes)
    dc.att_decrypt_final

    expect(decBuf.equals?(data)).to be true

    expect {

      wrsk = CcipherFactory::DerivedSymKey.from_encoded(skBin) do |ops|
        case ops
        when :password
          "password"
        end
      end
      dc = subject.att_decryptor
      decBuf = MemBuf.new
      dc.output(decBuf)
      dc.key = wrsk
      dc.att_decrypt_init
      dc.att_decrypt_update(encBuf.bytes)
      dc.att_decrypt_final

    }.to raise_exception(CcipherFactory::SymKeyDecryptionError)

    #expect(decBuf.string != data).to be true

    sk.activate_password_verifier
    skBin = sk.encoded

    expect {
      CcipherFactory::DerivedSymKey.from_encoded(skBin) do |ops|
        case ops
        when :pre_verify_password
          true
        when :password
          "password"
        end
      end
    }.to raise_exception(CcipherFactory::SymKey::SymKeyError)

  end


  it 'performs attached encryption and decryption on derivedsymkey with compression on' do
   
    data = File.read('spec/symkey_att_cipher_spec.rb')

    sk = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    c = subject.att_encryptor
    c.compression_on

    encBuf = MemBuf.new
    c.output(encBuf)
    c.key = sk
    c.att_encrypt_init
    c.att_encrypt_update(data)
    c.att_encrypt_final

    skBin = sk.encoded

    expect(encBuf.bytes.length > 0).to be true

    rsk = CcipherFactory::DerivedSymKey.from_encoded(skBin) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    dc = subject.att_decryptor
    decBuf = MemBuf.new
    dc.output(decBuf)
    dc.key = rsk
    dc.att_decrypt_init
    dc.att_decrypt_update(encBuf.bytes)
    dc.att_decrypt_final

    expect(decBuf.equals?(data)).to be true

    expect {
      # compression error shall throw first before end of process
      wrsk = CcipherFactory::DerivedSymKey.from_encoded(skBin) do |ops|
        case ops
        when :password
          "wrong key"
        end
      end
      dc = subject.att_decryptor
      decBuf = MemBuf.new
      dc.output(decBuf)
      dc.key = wrsk
      dc.att_decrypt_init
      dc.att_decrypt_update(encBuf.bytes)
      dc.att_decrypt_final

      expect(decBuf.equals?(data)).to be false

    }.to raise_exception(CcipherFactory::SymKeyDecryptionError)

    sk.activate_password_verifier
    skBin = sk.encoded

    expect {
      CcipherFactory::DerivedSymKey.from_encoded(skBin) do |ops|
        case ops
        when :pre_verify_password
          true
        when :password
          "password"
        end
      end
    }.to raise_exception(CcipherFactory::SymKey::SymKeyError)

  end


end
