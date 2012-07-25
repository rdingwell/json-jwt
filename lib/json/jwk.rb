module JSON
  module JWK 
    class Key < Hash

      def initialize(args)
        super
      end
      
      def [](key)
        super || with_indifferent_access[key]
      end
         
      def kid
        self['kid']
      end
     
      def use
        self['use']
      end
      
      def alg
        self['alg']
      end
            
      def to_key
       key =  case self.alg.to_sym
          when :RSA
            to_rsa_key
          when :EC
            to_ec_key
          else         
        end
        key
      end
      
      private       
      
      def to_rsa_key
        key = OpenSSL::PKey::RSA.new
        exponent = OpenSSL::BN.new decode(self[:exp])
        modulus = OpenSSL::BN.new decode(self[:mod])
        key.e = exponent
        key.n = modulus
        key
      end
      
      def to_ec_key
        raise NotImplementedError.new
      end
      
      def decode(str)
         UrlSafeBase64.decode64(str).unpack('B*').first.to_i(2).to_s
      end
            
    end
    
    class KeySet 
      attr_accessor :keys
      def initialize(keys = [])
        @keys = keys
      end
      
     def [](kid)
        keys.find{|k| k["kid"] == keid}
      end

      def find(use,alg)
        keys = @keys.find{|k| k.use==use && k.alg==alg}
        keys.nil? ? nil : keys[0]
      end

    end

    def self.parse_url(url)
      jwk_str = open(url).read
      json = JSON.parse(jwk_str)
      keys = json["keys"] || []
      KeySet.new(keys.collect{|k| Key.new(nil).merge k})    
    end
    
  end
  
end
