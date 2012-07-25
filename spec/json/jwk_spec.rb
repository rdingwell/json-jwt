require 'spec_helper'

describe JSON::JWK do
  let(:jwk) {JSON::JWK.parse_url './spec/fixtures/jwk/key_set.json'}
  
  describe "#parse" do
     it do
       jwk.keys.length.should == 2
       jwk.keys.each do |k|
         if k.alg == "EC"
           pending "EC NOT IMPLEMENTED"
         else
          k.to_key.should_not == nil
          k.to_key.kind_of?(OpenSSL::PKey::RSA).should == true
        end
       end
     end
  end
end