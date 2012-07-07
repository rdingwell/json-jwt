module JSON
  class JWE < JWT
    class InvalidFormat < JWT::InvalidFormat; end
    class VerificationFailed < JWT::VerificationFailed; end
    include JSON::JWA::JWE
    
    attr_accessor :cipher_text
    attr_accessor :data
    attr_accessor :encrypted_key
    attr_accessor :cmk
    attr_accessor :iv
    def initialize(jwt)
      @header = { :alg => :RSA1_5,
                  :enc => :A256CBC,
                  :int => :HS256,
                  :type => :JWE
      }
      
    end

    def encrypt(key, kid=nil)
      raise JSON::JWA::InvalidAlgorithmException.new(algorithm) unless valid_alg?(algorithm)
      raise JSON::JWA::InvalidEncodingException.new unless valid_enc?(encoding)
      
      header[:kid] = kid
      generate_cmk(encoding)
      cek,cik = derive_keys(cmk,1) 
      @encrypted_key = encrypt_cmk(key,cmk)
      cipher = generate_cipher(openssl_encoding(encoding),true, cek, ivec)
      @cipher_text = cipher.update(data)
      @cipher_text << cipher.final
      sb = signature_base_string
      
      aead?(encoding) ? sb + "." : "#{sb}.#{UrlSafeBase64.encode64(sign(sb,cik))}"
    end
    
    def decrypt(key)
      alg = header[:enc]
      cmk = decrypt_cmk(key, encrypted_key)
      cek,cik = derive_keys(cmk,1)
      unless aead?(encoding) 
        verify(cik)
      end
      cipher = generate_cipher(openssl_encoding(encoding),false, cek, ivec)
      data = cipher.update(cipher_text)
      data << cipher.final
      data
    end
    

    def signature_base_string
      [header.to_json,encrypted_key,cipher_text].collect do |segment|
        UrlSafeBase64.encode64(segment)
      end.join(".")
    end


    def verify(cik)
      raise "Verification Error" unless iv == OpenSSL::HMAC.digest( digest(integrity), cik, signature_base_string)
      true
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
      
      jwe = JWE.new nil
      jwe.header = JSON.parse(header)
      jwe.cipher_text = cipher_text
      jwe.encrypted_key = encrypted_key
      jwe.iv = iv
      kid = jwe.header['kid']
      key = case key_or_set
           when  JSON::JWK::KeySet
             (key_or_set.keys.length == 1) ? key_or_set.keys[0] : key_or_set[kid].to_key
            else
              key_or_set
            end 
      # jwe.decrypt(key)
      jwe
    end
    
  
    def algorithm
      header[:alg] || header['alg']
    end
    
    def integrity
      header[:int] || header['int']
    end
    

    def encoding
      header[:enc] ||  header["enc"]
    end


    def ivec
      _ivec = (header[:iv] ||  header["iv"])
      _ivec.nil? ? nil : UrlSafeBase64.decode64(_ivec)
    end
    
    def generate_cmk(alg)
      cipher = OpenSSL::Cipher::Cipher.new(openssl_encoding(alg))
      @cmk = OpenSSL::Random.random_bytes(cipher.key_len)
      iv = OpenSSL::Random.random_bytes(cipher.iv_len)
      header[:iv] = UrlSafeBase64.encode64(iv)
    end

    def generate_cipher(enc, encrypt, key, ivec)
      cipher = OpenSSL::Cipher::Cipher.new(enc)
      if encrypt 
        cipher.encrypt 
      else
        cipher.decrypt
      end
      cipher.key = key
      cipher.iv = ivec
      cipher
    end
    
    def derive_keys(cmk,key_length)
      [derive_key(cmk,key_length,"Encryption"),derive_key(cmk,key_length,"Integrity")]
    end
    
    def derive_key(cmk,key_length,pubSuppInfo)
      cmk
    end
    
    
    def encrypt_cmk(key, cipher)
      key.private? ? key.private_encrypt(cipher) : key.public_encrypt(cipher)
    end
  
  
    def decrypt_cmk(key,encrypted_cek)
      cmk = key.private? ? key.private_decrypt(encrypted_key) : key.public_decrypt(encrypted_key)
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
        OpenSSL::HMAC.digest digest(integrity), secret, signature_base_string
      else
        raise InvalidFormat.new('Signature Must be an HMAC algorithm')
      end
    end  
  end
end
