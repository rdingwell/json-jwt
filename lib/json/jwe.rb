module JSON
  class JWE < JWT
    class InvalidFormat < JWT::InvalidFormat; end
    class VerificationFailed < JWT::VerificationFailed; end
    include JSON::JWA::JWE
    
    attr_accessor :cipher_text
    attr_accessor :data
    attr_accessor :iv
    attr_accessor :encrypted_key
    attr_accessor :cmk
    
    def initialize(jwt)
      @header = { :alg => :RS,
                  :enc => :AES256CBC,
                  :type => :JWE
      }
      
    end

    def encrypt(key, kid=nil)
      raise JSON::JWA::InvalidAlgorithmException.new(algorithm) unless valid_alg?(algorithm)
      raise JSON::JWA::InvalidEncodingException.new unless valid_enc?(encoding)
      
      header[:kid] = kid
      generate_cmk(encoding)
      cek,cik = derive_keys(cmk,1) 
      encrypted_key = encrypt_cek(key,cmk,algorithm)
      cipher = generate_cipher(encoding,true, cek, header[:iv])
      cipher_text = cipher.update(data)
      cipher_text << cipher.final
      sb = signature_base_string
      
      aead?(encoding) ? sb + "." : "#{sb}.#{sign(sb,cik,integrity)}"
    end
    
    def decrypt(key)
      alg = header[:enc]
      cmk = decrypt_cmk(key, encrypted_key,alg)
      cek,cik = derive_keys(cmk,1)
      unless aead?(encoding) 
        verify(cik)
      end
      cipher = generate_cipher(encoding,false, cek, header[:iv])
      data = cipher.update(Base64.strict_decode64(edata))
      data << cipher.final
      data
    end
    

    def signature_base_string
      [header.to_json,encrypted_key,cipher_text].collect do |segment|
        UrlSafeBase64.encode(segment)
      end.join(".")
    end


    def verify(cik)
      raise "Verification Error" unless iv == OpenSSL::HMAC.digest( digest(integrity), cik, signature_base_string)
    end
    
    def self.encrypt(data,key,alg,enc,int=nil, kid=nil)
       jwe = JWE.new({})
       jwe.header[:alg] = alg
       jwe.header[:enc] = enc
       jwe.header[:int] = int
       jwe.data = data
       jwe.encrypt(key,kid)    
    end
    
    def self.decode(jwe_string, key_or_set)
      raise InvalidFormat.new('Invalid JWT Format. JWT should include 3 dots.') unless jwe_string.count('.') == 3
      header, encrypted_key, cipher_text, iv = jwe_string.split('.', 4).collect do |segment|
        UrlSafeBase64.decode64 segment.to_s
      end
      
      jwe = JWE.new
      jwe.header = JSON.parse(header)
      jwe.cipher_text = cipher_text
      jwe.encrypted_key = encrypted_key
      jwe.iv = iv
      kid = jwe.header['kid']
      key = case key_or_set
           when  KeySet
             (key_or_set.keys.length == 1) ? key_or_set.keys[0] : key_or_set[kid].to_key
            else
              key_or_set
            end 
      jwe.decrypt(key)
      jwe
    end
    
    
    private 
    
  
    def algorithm
      header[:alg]
    end
    
    def integrity
        header[:int]
    end
    

    def encoding
      header[:enc]
    end


    def generate_cmk(alg)
      cipher = OpenSSL::Cipher::Cipher.new(alg)
      cmk = OpenSSL::Random.random_bytes(cipher.key_len)
      header[:iv] = OpenSSL::Random.random_bytes(cipher.iv_len)
    end

    def generate_cipher(alg, encrypt, key, iv)
      cipher = OpenSSL::Cipher::Cipher.new(alg)
      if encrypt 
        cipher.encrypt 
      else
        cipher.decrypt
      end
      cipher.key = key
      cipher.iv = iv
      cipher
    end
    
    def derive_keys(cmk,key_length)
      [derive_key(cmk,key_length,"Encryption"),derive_key(cmk,key_length,"Integrity")]
    end
    
    def derive_key(cmk,key_length,pubSuppInfo)
      cipher
    end
    
    
    def encrypt_cmk(key, cipher)
      key.public_encrypt(cipher.key)
    end
  
  
    def decrypt_cmk(key,encrypted_cek)
      cmk = key.public_decrypt(encrypted_key)
      cmk
    end
    
    
    def digest(alg)
      OpenSSL::Digest::Digest.new "SHA#{alg.to_s[2, 3]}"
    end

    def hmac?(alg)
      [:HS256, :HS384, :HS512].collect(&:to_s).include? alg.to_s
    end
      
      
    def sign(signature_base_string, private_key_or_secret)        
      if valid_int?(integrity)
        secret = private_key_or_secret
        OpenSSL::HMAC.digest digest, secret, signature_base_string
      else
        raise InvalidFormat.new('Signature Must be an HMAC algorithm')
      end
    end  
  end
end
