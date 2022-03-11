

require_relative '../lib/ccipher_factory/symkey/symkey_generator'
require_relative '../lib/ccipher_factory/symkey_cipher/symkey_cipher'

RSpec.describe CcipherFactory::SymKeyCipher do

  it 'encrypts given data with softsymkey internal' do
  
    #spec = [
    #  [:aes, 128],
    #  [:aes, 128, :gcm],

    #  [:aes, 256],
    #  [:aes, 256, :gcm],

    #  [:aes, 256],
    #  [:aes, 256, :cbc],

    #  [:aes, 256],
    #  [:aes, 256, :gcm],

    #  [:chacha20_poly1305, 256],
    #  [:chacha20_poly1305, 256],

    #  [:blowfish, 128],
    #  [:blowfish, 128, :cbc],

    #  [:camellia, 256],
    #  [:camellia, 256, :ctr],

    #]

    data = "DSuper Secret!"

    CcipherFactory::SymKeyGenerator.supported_symkey.each do |k,v|

      v[0].each do |ks|

        if v[1].length == 0

          puts "Testing config : #{k}-#{ks}"
          sk = CcipherFactory::SymKeyGenerator.generate(k, ks)
          p sk
          c = subject.encryptor
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
          dec.decrypt_update_cipher(encBuf.string)
          dec.decrypt_final

          puts decBuf.string if decBuf.string != data
          expect(decBuf.string == data).to be true

          # external key
          skBin = sk.to_asn1
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
          dec2.decrypt_update_cipher(encBuf.string)
          dec2.decrypt_final

          expect(decBuf2.string == data).to be true

          # attached mode for symkey
          sk.attach_mode
          skBin = sk.to_asn1
          rsk2 = CcipherFactory::SoftSymKey.from_asn1(skBin)
          expect(rsk2.key == sk.key).to be true
          dec3 = subject.decryptor
          expect(dec3).not_to be_nil
          decBuf3 = MemBuf.new
          dec3.output(decBuf3)
          dec3.key = rsk2
          dec3.decrypt_init
          dec3.decrypt_update_meta(meta)
          dec3.decrypt_update_cipher(encBuf.string)
          dec3.decrypt_final

          expect(decBuf3.string == data).to be true


        else

          v[1].each do |mode|
            puts "Testing config : #{k}-#{ks}-#{mode}"
            #sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)
            sk = CcipherFactory::SymKeyGenerator.generate(k, ks)
            c = subject.encryptor
            c.mode = mode
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
            dec.decrypt_update_cipher(encBuf.string)
            dec.decrypt_final

            p decBuf.string
            expect(decBuf.string == data).to be true

            # external key
            skBin = sk.to_asn1
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
            dec2.decrypt_update_cipher(encBuf.string)
            dec2.decrypt_final

            expect(decBuf2.string == data).to be true

            # attached mode for symkey
            sk.attach_mode
            skBin = sk.to_asn1
            rsk2 = CcipherFactory::SoftSymKey.from_asn1(skBin)
            expect(rsk2.key == sk.key).to be true
            dec3 = subject.decryptor
            expect(dec3).not_to be_nil
            decBuf3 = MemBuf.new
            dec3.output(decBuf3)
            dec3.key = rsk2
            dec3.decrypt_init
            dec3.decrypt_update_meta(meta)
            dec3.decrypt_update_cipher(encBuf.string)
            dec3.decrypt_final

            expect(decBuf3.string == data).to be true


          end

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


    sk = CcipherFactory::SymKeyGenerator.generate(:blowfish, 256)
    c = subject.encryptor
    encBuf = MemBuf.new
    c.output(encBuf)
    c.key = sk
    # invalid keysize
    expect { c.encrypt_init }.to raise_exception(ArgumentError)

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
    dec.decrypt_update_cipher(encBuf.string)
    dec.decrypt_final

    expect(decBuf.string == fileContent).to be true

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
    dec.decrypt_update_cipher(encBuf.string)
    dec.decrypt_final

    expect(decBuf.string == data).to be true

    # external key
    skBin = sk.to_asn1
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
    dec2.decrypt_update_cipher(encBuf.string)
    dec2.decrypt_final

    expect(decBuf2.string == data).to be true

    # attached mode
    sk.attach_mode
    skBin = sk.to_asn1
    rsk2 = CcipherFactory::SoftSymKey.from_asn1(skBin)
    expect(rsk2.key == sk.key).to be true
    dec3 = subject.decryptor
    expect(dec3).not_to be_nil
    decBuf3 = MemBuf.new
    dec3.output(decBuf3)
    dec3.key = rsk2
    dec3.decrypt_init
    dec3.decrypt_update_meta(meta)
    dec3.decrypt_update_cipher(encBuf.string)
    dec3.decrypt_final

    expect(decBuf3.string == data).to be true

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

    skBin = sk.to_asn1
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
    dec.decrypt_update_cipher(encBuf.string)
    dec.decrypt_final

    expect(decBuf.string == data).to be true

    sk.activate_password_verifier
    skBin = sk.to_asn1

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
    dec.decrypt_update_cipher(encBuf.string)
    expect {
      dec.decrypt_final
    }.to raise_exception(CcipherFactory::SymKeyDecryptionError)

    p decBuf.string
    p data
    expect(decBuf.string != data).to be true

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
