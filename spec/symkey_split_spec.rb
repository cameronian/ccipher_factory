


RSpec.describe CcipherFactory::SymKeyGenerator do

  it 'generates soft symkey and splits and joins shares' do
   
    sk = subject.generate(:aes, 256)
 
    totalShare = 2
    reqShare = 1

    shares = sk.split_key(totalShare, reqShare)
    expect(shares.length == totalShare).to be true

    rkey = CcipherFactory::SoftSymKey.new(:aes, 256)
    rkey.merge_key([shares[1]])

    expect(sk.key == rkey.key).to be true

    totalShare = 5
    reqShare = 3

    shares = sk.split_key(totalShare, reqShare)
    expect(shares.length == totalShare).to be true

    rk2 = CcipherFactory::SoftSymKey.new(:aes, 256)

    cnt = 0
    while (cnt < 20) do
      rk2.merge_key(shares.sample(reqShare))
      expect(rk2.key == sk.key).to be true
      cnt += 1
    end

    expect {rk2.merge_key(shares.sample(reqShare-1)) }.to raise_exception(CcipherFactory::ShamirSharingHelper::NotEnoughShare)

  end

end
