


RSpec.describe CcipherFactory::AsymKeyGenerator do
  
  it 'generates soft ECC keypair' do
   
    ec = subject.generate(:ecc)
    expect(ec).not_to be_nil
    expect(ec.is_a?(CcipherFactory::KeyPair::ECCKeyPair)).to be true
    expect(ec.curve == subject.algo_default(:ecc)[:curve]).to be true

    subject.supported_asymkey[:ecc].each do |c|
      puts "Generating ECC curve #{c}"
      ec = subject.generate(:ecc, { curve: c })
      expect(ec).not_to be_nil
      expect(ec.is_a?(CcipherFactory::KeyPair::ECCKeyPair)).to be true
      expect(ec.curve == c.curve).to be true
    end

  end

end
