

RSpec.describe CcipherFactory::KCV do

  it 'creates KCV based on input and verifies it' do
  
    key = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end
    
    kcv = subject
    kcv.key = key

    kcvBin = kcv.encoded

    rkcv = subject.class.from_asn1(kcvBin)
    rkcv.key = key
    expect(rkcv.is_matched?).to be true

  end

end
