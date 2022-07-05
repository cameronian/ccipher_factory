

RSpec.describe CcipherFactory::AsymKeyCipher do

  it 'attached encrypts and decrypts for ECC recipients' do
  
    recp = CcipherFactory::AsymKeyGenerator.generate(:ecc)

    data = "Super secret message for ECC recipient for attached cipher!"
    enc = subject.att_encryptor(:ecc)

    out = MemBuf.new
    enc.output(out)
    enc.sender_keypair = recp
    enc.recipient_key = recp.public_key

    enc.att_encrypt_init #({ recipient_public: recp.public_key })
    enc.att_encrypt_update(data)
    ts = enc.att_encrypt_final

    dec = subject.att_decryptor(:ecc)
    dout = MemBuf.new
    dec.output(dout)
    dec.decryption_key = recp

    dec.att_decrypt_init #(recp)
    dec.att_decrypt_update(out.bytes)
    dec.att_decrypt_final

    expect(dout.equals?(data)).to be true

  end

  it 'attached encrypts and decrypts for ECC recipients with compression on' do
  
    recp = CcipherFactory::AsymKeyGenerator.generate(:ecc)

    data = "Super secret message for ECC recipient for attached cipher!"
    enc = subject.att_encryptor(:ecc)

    out = MemBuf.new
    enc.output(out)

    dig = CcipherFactory::Digest.instance
    digOut = MemBuf.new
    dig.output(digOut)
    dig.digest_init

    enc.compression_on
    enc.sender_keypair = recp
    enc.recipient_key = recp.public_key
    enc.att_encrypt_init #({ recipient_public: recp.public_key })
    contLength = 0
    File.open("spec/symkey_cipher_spec.rb","r") do |f|
      cont = f.read
      contLength = cont.length
      puts "input : #{cont.length}"
      dig.digest_update(cont)
      enc.att_encrypt_update(cont)
    end
    ts = enc.att_encrypt_final
    puts "enc out: #{out.bytes.length}"

    digRes = dig.digest_final

    dec = subject.att_decryptor(:ecc)
    dout = MemBuf.new
    dec.output(dout)
    dec.decryption_key = recp

    dec.att_decrypt_init #(recp)
    dec.att_decrypt_update(out.bytes)
    dec.att_decrypt_final

    dig2 = CcipherFactory::Digest.from_encoded(digRes)
    dig2Out = MemBuf.new
    dig2.output(dig2Out)
    dig2.digest_update(dout.bytes)
    dig2.digest_final

    puts "decrypted length : #{dout.bytes.length}"

    expect(digOut.bytes == dig2Out.bytes).to be true
    expect(dout.bytes.length == contLength).to be true

  end


end
