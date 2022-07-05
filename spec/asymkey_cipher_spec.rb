

RSpec.describe CcipherFactory::AsymKeyCipher do

  it 'encrypts and decrypts for ECC recipients with no compression' do

    cnt = 0
    loop do

      recp = CcipherFactory::AsymKeyGenerator.generate(:ecc)

      data = "Super secret message for ECC recipient!"
      enc = subject.encryptor(:ecc)

      out = MemBuf.new
      enc.output(out)
      enc.sender_keypair = recp
      enc.recipient_key = recp.public_key
      enc.encrypt_init 
      enc.encrypt_update(data)
      ts = enc.encrypt_final

      dec = subject.decryptor(:ecc)

      dout = MemBuf.new
      dec.output(dout)
      dec.decryption_key = recp

      dec.decrypt_init
      dec.decrypt_update_meta(ts)
      dec.decrypt_update_cipher(out.bytes)
      dec.decrypt_final

      expect(dout.equals?(data)).to be true

      cnt += 1

      puts "\nLoop #{cnt}\n"

      break if cnt >= 1
    end

  end

  it 'encrypts and decrypts file for ECC recipients with compression on' do
 
    cnt = 0
    loop do

      recp = CcipherFactory::AsymKeyGenerator.generate(:ecc)

      enc = subject.encryptor(:ecc)
      out = MemBuf.new
      enc.output(out)

      dig = CcipherFactory::Digest.instance
      digOut = MemBuf.new
      dig.output(digOut)
      dig.digest_init

      enc.compression_on
      enc.sender_keypair = recp
      enc.recipient_key = recp.public_key

      enc.encrypt_init

      contLength = 0
      File.open("spec/symkey_cipher_spec.rb","r") do |f|
        cont = f.read
        contLength = cont.length
        puts "input : #{cont.length}"
        dig.digest_update(cont)
        enc.encrypt_update(cont)
      end
      ts = enc.encrypt_final
      puts "enc out: #{out.bytes.length}"

      digRes = dig.digest_final

      dec = subject.decryptor(:ecc)
      dout = MemBuf.new
      dec.output(dout)
      dec.decryption_key = recp

      dec.decrypt_init
      dec.decrypt_update_meta(ts)
      dec.decrypt_update_cipher(out.bytes)
      dec.decrypt_final

      dig2 = CcipherFactory::Digest.from_encoded(digRes)
      dig2Out = MemBuf.new
      dig2.output(dig2Out)
      dig2.digest_update(dout.bytes)
      dig2.digest_final

      puts "decrypted length : #{dout.bytes.length}"

      expect(digOut.bytes == dig2Out.bytes).to be true
      expect(dout.bytes.length == contLength).to be true

      cnt += 1

      puts "\nLoop #{cnt}\n"
      break if cnt >= 1
    end
  end

end
