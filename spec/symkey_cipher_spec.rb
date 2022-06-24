

require_relative '../lib/ccipher_factory/symkey/symkey_generator'
require_relative '../lib/ccipher_factory/symkey_cipher/symkey_cipher'

RSpec.describe CcipherFactory::SymKeyCipher do

  it 'encrypts given data with softsymkey internal' do
  
    data = "DSuper Secret!"

    comp = Ccrypto::UtilFactory.instance(:comparator)
    CcipherFactory::SymKeyGenerator.supported_symkey.each do |k,v|

      v[:keysize].each do |ks|

        v[:mode].each do |m|

          puts "Testing config : #{k}-#{ks}-#{m}"
          sk = CcipherFactory::SymKeyGenerator.generate(k, ks)
          c = subject.encryptor
          c.mode = m
          c.key = sk

          encBuf = MemBuf.new
          c.output(encBuf)

          c.encrypt_init
          c.encrypt_update(data)
          meta = c.encrypt_final

          dec = subject.decryptor
          expect(dec).not_to be_nil
          decBuf = MemBuf.new
          dec.output(decBuf)
          dec.key = sk
          dec.decrypt_init
          dec.decrypt_update_meta(meta)
          dec.decrypt_update_cipher(encBuf.bytes)
          dec.decrypt_final

          if decBuf.bytes != data
            puts decBuf.bytes 
            puts data
          end
          #expect(decBuf.bytes == data).to be true
          expect(comp.is_equals?(decBuf.bytes,data)).to be true

          # external key
          skBin = sk.encoded
          rsk = CcipherFactory::SoftSymKey.from_asn1(skBin) do |ops|
            case ops
            when :key
              sk.key
            end
          end
          expect(rsk.key == sk.key).to be true
          dec2 = subject.decryptor
          expect(dec2).not_to be_nil
          decBuf2 = MemBuf.new
          dec2.output(decBuf2)
          dec2.key = rsk
          dec2.decrypt_init
          dec2.decrypt_update_meta(meta)
          dec2.decrypt_update_cipher(encBuf.bytes)
          dec2.decrypt_final

          #expect(decBuf2.bytes == data).to be true
          expect(comp.is_equals?(decBuf2.bytes,data)).to be true

          # attached mode for symkey
          sk.attach_mode
          skBin = sk.encoded
          rsk2 = CcipherFactory::SoftSymKey.from_asn1(skBin)
          expect(comp.is_equals?(rsk2.key,sk.key.key)).to be true
          #expect(rsk2.key == sk.key.key).to be true
          dec3 = subject.decryptor
          expect(dec3).not_to be_nil
          decBuf3 = MemBuf.new
          dec3.output(decBuf3)
          dec3.key = rsk2
          dec3.decrypt_init
          dec3.decrypt_update_meta(meta)
          dec3.decrypt_update_cipher(encBuf.bytes)
          dec3.decrypt_final

          expect(decBuf3.equals?(data)).to be true


        end
      end

    end

  end

  it 'invalid symkey spec' do

    data = "Super secret word"

    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)
    c = subject.encryptor
    c.key = sk
    # encryption requires output to be set
    expect { c.encrypt_init }.to raise_exception(CcipherFactory::SymKeyCipherError)


    sk = CcipherFactory::SymKeyGenerator.generate(:aria, 512)
    c = subject.encryptor
    encBuf = MemBuf.new
    c.output(encBuf)
    c.key = sk
    # invalid keysize
    expect { c.encrypt_init }.to raise_exception(CcipherFactory::SymKeyCipherError)

    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 512)
    c = subject.encryptor
    encBuf = MemBuf.new
    c.output(encBuf)
    c.key = sk
    # No such algorithm spec AES-512-GCM
    expect { c.encrypt_init }.to raise_exception(CcipherFactory::SymKeyCipherError)


  end

  it 'compress and encrypt input' do

    target = "spec/digest_spec.rb"
    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)
    c = subject.encryptor
    encBuf = MemBuf.new
    c.output(encBuf)
    c.compression_on
    c.key = sk
    c.encrypt_init
    fileContent = ""
    File.open(target,"rb") do |f|
      fileContent = f.read
      c.encrypt_update(fileContent)
    end
    meta = c.encrypt_final

    dec = subject.decryptor
    expect(dec).not_to be_nil
    decBuf = MemBuf.new
    dec.output(decBuf)
    dec.key = sk
    dec.decrypt_init
    dec.decrypt_update_meta(meta)
    dec.decrypt_update_cipher(encBuf.bytes)
    dec.decrypt_final

    expect(decBuf.equals?(fileContent)).to be true

  end

  it 'encrypts given data with softsymkey external' do
   
    key = SecureRandom.random_bytes(256/8)

    data = "DSuper Secret!"
    sk = CcipherFactory::SoftSymKey.new(:aes, 256, key)
    c = subject.encryptor
    encBuf = MemBuf.new
    c.output(encBuf)
    c.key = sk
    c.encrypt_init
    c.encrypt_update(data)
    meta = c.encrypt_final

    dec = subject.decryptor
    expect(dec).not_to be_nil
    decBuf = MemBuf.new
    dec.output(decBuf)
    dec.key = sk
    dec.decrypt_init
    dec.decrypt_update_meta(meta)
    dec.decrypt_update_cipher(encBuf.bytes)
    dec.decrypt_final

    expect(decBuf.equals?(data)).to be true

    # external key
    skBin = sk.encoded
    rsk = CcipherFactory::SoftSymKey.from_asn1(skBin) do |ops|
      case ops
      when :key
        key
      end
    end
    expect(rsk.key == sk.key).to be true
    dec2 = subject.decryptor
    expect(dec2).not_to be_nil
    decBuf2 = MemBuf.new
    dec2.output(decBuf2)
    dec2.key = rsk
    dec2.decrypt_init
    dec2.decrypt_update_meta(meta)
    dec2.decrypt_update_cipher(encBuf.bytes)
    dec2.decrypt_final

    expect(decBuf2.equals?(data)).to be true

    # attached mode
    sk.attach_mode
    skBin = sk.encoded
    rsk2 = CcipherFactory::SoftSymKey.from_asn1(skBin)
    comparator = Ccrypto::UtilFactory.instance(:comparator)
    expect(comparator.is_equal?(rsk2.key, sk.key)).to be true
    dec3 = subject.decryptor
    expect(dec3).not_to be_nil
    decBuf3 = MemBuf.new
    dec3.output(decBuf3)
    dec3.key = rsk2
    dec3.decrypt_init
    dec3.decrypt_update_meta(meta)
    dec3.decrypt_update_cipher(encBuf.bytes)
    dec3.decrypt_final

    expect(decBuf3.equals?(data)).to be true

  end

  it 'encrypts given data with derivedsymkey' do
   
    data = "DSuper Secret!"
    sk = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    c = subject.encryptor
    encBuf = MemBuf.new
    c.output(encBuf)
    c.key = sk
    c.encrypt_init
    c.encrypt_update(data)
    meta = c.encrypt_final

    skBin = sk.encoded
    rsk = CcipherFactory::DerivedSymKey.from_asn1(skBin) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    dec = subject.decryptor
    expect(dec).not_to be_nil
    decBuf = MemBuf.new
    dec.output(decBuf)
    dec.key = rsk
    dec.decrypt_init
    dec.decrypt_update_meta(meta)
    dec.decrypt_update_cipher(encBuf.bytes)
    dec.decrypt_final

    expect(decBuf.equals?(data)).to be true

    sk.activate_password_verifier
    skBin = sk.encoded

    wdk = CcipherFactory::DerivedSymKey.from_asn1(skBin) do |ops|
      case ops
      when :password
        "password"
      end
    end
    dec = subject.decryptor
    expect(dec).not_to be_nil
    decBuf = MemBuf.new
    dec.output(decBuf)
    dec.key = wdk
    dec.decrypt_init
    dec.decrypt_update_meta(meta)
    dec.decrypt_update_cipher(encBuf.bytes)
    expect {
      dec.decrypt_final
    }.to raise_exception(CcipherFactory::SymKeyDecryptionError)

    expect(decBuf.equals?(data)).to be false

    expect { 
      CcipherFactory::DerivedSymKey.from_asn1(skBin) do |ops|
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
