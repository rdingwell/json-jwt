module JSON
  module JWA
    class InvalidAlgorithmException < StandardError; end
    class InvalidEncodingException < StandardError; end
        
    module JWS
      ALG = [:HS128, :HS256, :HS384, :HS512, :RS128, :RS256, :RS384, :RS512, :ES128, :ES256, :ES384,:ES512, :none] 
      
      def valid_alg?(alg)
        ALG.collect(&:to_s).include? alg.to_s
      end

    end

    module JWE
      ALG = [:RSA1_5, "RSA-OAEP", "ECDH-ES",:A128KW, :A256KW]
      ENC = [:A128CBC ,:A256CBC, :A128GCM, :A256GCM]
      INT = [:HS256, :HS384, :HS512]

      def valid_alg?(alg)
        ALG.collect(&:to_s).include? alg.to_s
      end

      def valid_enc?(alg)
        ENC.collect(&:to_s).include? alg.to_s
      end

      def valid_int?(alg)
        INT.collect(&:to_s).include? alg.to_s
      end
      
      def aead?(alg)
        [:A128GCM, :A256GCM].collect(&:to_s).include? alg.to_s
      end
      
      def openssl_encoding(encoding)
        if valid_enc?(encoding)
         return "aes-#{encoding.to_s[1,3]}-#{encoding.to_s[4,3]}".downcase
        end
    end
  end

    def self.generate_digest(alg)
       OpenSSL::Digest::Digest.new "SHA#{alg.to_s[2, 3]}"
    end

    def self.hmac?(alg)
      alg_check(alg,"HS")
    end

    def self.aead?(alg)
      [:A128GCM, :A256GCM].collect(&:to_s).include? alg.to_s
    end

    def self.rsa?(alg)
      alg_check(alg,"RS")
    end

    def self.ec?(alg)
      alg_check(alg,"ES")
    end

    def self.alg_check(alg, type)
     alg.to_s[0,2].upcase == type.to_s.upcase
    end 
    
    def self.type?(alg)
        
    end

  end
end
