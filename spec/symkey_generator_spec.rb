

require_relative '../lib/ccipher_factory/symkey/symkey'
require_relative '../lib/ccipher_factory/symkey/symkey_generator'

RSpec.describe CcipherFactory::SymKeyGenerator do

  let(:symkey) { CcipherFactory::SymKey }
  let(:ssymkey) { CcipherFactory::SoftSymKey }
  let(:dsymkey) { CcipherFactory::DerivedSymKey }

  it 'generates AES symmetric key' do
    
    sk = subject.generate(:aes, 256)  
    expect(sk).not_to be_nil
    expect(sk.is_a?(CcipherFactory::SymKey)).to be true

    expect(sk.keysize == 256).to be true
    expect(sk.key).not_to be_nil
    expect((sk.key.length*8) == sk.keysize).to be true

    skBin = sk.encoded
    expect { ssymkey.from_asn1(skBin) }.to raise_exception(CcipherFactory::SymKey::SymKeyError)

    rsk = ssymkey.from_asn1(skBin) do |ops|
      case ops
      when :key
        sk.key
      end
    end
    expect(rsk.keytype == sk.keytype).to be true
    expect(rsk.keysize == sk.keysize).to be true
    expect(rsk.key == sk.key).to be true

    sk.attach_mode
    skBin2 = sk.encoded
    rsk2 = ssymkey.from_asn1(skBin2)
    expect(rsk2.keytype == sk.keytype).to be true
    expect(rsk2.keysize == sk.keysize).to be true
    expect(rsk2.key).not_to be_empty
    expect(sk.key.equals?(rsk2.key)).to be true

  end

  it 'generates AES derived Symmetric Key' do

    sk = subject.derive(:aes, 256) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    expect(sk).not_to be_nil
    expect(sk.is_a?(CcipherFactory::DerivedSymKey)).to be true

    skBin = sk.encoded
    expect(skBin).not_to be_nil
    rsk = dsymkey.from_asn1(skBin) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    expect(rsk).not_to be_nil
    expect(rsk.key).not_to be_nil
    expect(rsk.key.length > 0).to be true
    expect(rsk.keytype == sk.keytype).to be true
    expect(rsk.keysize == sk.keysize).to be true
    expect(rsk.key == sk.key).to be true

    irsk = dsymkey.from_asn1(skBin) do |ops|
      case ops
      when :password
        "p@ssw0rdasdf"
      end
    end
    expect(irsk.key != sk.key).to be true

  end

  it 'generates AES derived Symmetric Key with password verifier activated' do

    sk = subject.derive(:aes, 256) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    expect(sk).not_to be_nil
    expect(sk.is_a?(CcipherFactory::DerivedSymKey)).to be true

    # activate password verification
    # need user specifically turned on unsafe behavior
    sk.activate_password_verifier

    skBin = sk.encoded
    expect(skBin).not_to be_nil
    rsk = dsymkey.from_asn1(skBin) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    expect(rsk).not_to be_nil
    expect(rsk.key).not_to be_nil
    expect(rsk.key.length > 0).to be true
    expect(rsk.keytype == sk.keytype).to be true
    expect(rsk.keysize == sk.keysize).to be true
    expect(rsk.key == sk.key).to be true

    expect {
      dsymkey.from_asn1(skBin) do |ops|
        case ops
        when :pre_verify_password   # need user specifically turned on unsafe behavior
          true
        when :password
          "p@ssw0rdasdf"
        end
      end
    }.to raise_exception(CcipherFactory::SymKey::SymKeyError)

  end


  it 'generates all supported symkey type' do

    subject.supported_symkey.each do |k,v|

      v[:keysize].each do |ks|
      #v[0].each do |ks|

        puts "Generating Key #{k}-#{ks}"

        sk = subject.generate(k,ks)  
        expect(sk).not_to be_nil
        expect(sk.is_a?(CcipherFactory::SymKey)).to be true

        expect(sk.keysize == ks).to be true
        expect(sk.key).not_to be_nil
        expect((sk.key.length*8) == sk.keysize).to be true

        skBin = sk.encoded
        expect { ssymkey.from_asn1(skBin) }.to raise_exception(CcipherFactory::SymKey::SymKeyError)

        rsk = ssymkey.from_asn1(skBin) do |ops|
          case ops
          when :key
            sk.key
          end
        end
        expect(rsk.keytype == sk.keytype).to be true
        expect(rsk.keysize == sk.keysize).to be true
        expect(rsk.key == sk.key).to be true

        sk.attach_mode
        skBin2 = sk.encoded
        rsk2 = ssymkey.from_asn1(skBin2)
        expect(rsk2.keytype == sk.keytype).to be true
        expect(rsk2.keysize == sk.keysize).to be true
        expect(rsk2.key).not_to be_empty
        p sk.key.class
        #expect(rsk2.key == sk.key).to be true
        expect(sk.key.equals?(rsk2.key)).to be true

      end

    end
    
  end

end
