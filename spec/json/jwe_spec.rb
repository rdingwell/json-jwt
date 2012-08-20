require 'spec_helper'

describe JSON::JWE do
  
  let(:jwe) {
    
     _jwt_ = JSON::JWE.new({})
     _jwt_.data = "hey thar"
     _jwt_
  }
  
  
  describe "#encrypt_decrypt" do
     it "should be able to do a round trip encrypt decrypt" do
       d = jwe.encrypt(public_key)
       dec = JSON::JWE.decode(d,private_key)
       dec.data.should == jwe.data
     end
  end
  
  describe "#decrypt" do
     it :TODO
  end
  
  
  describe "#generate_cipher" do
    it :TODO
  end
  
  
end