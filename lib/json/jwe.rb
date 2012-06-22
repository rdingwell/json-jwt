module JSON
  class JWE < JWT
    attr_accessor :cipher_text
    attr_accessor :data
    attr_accessor :iv
    attr_accessor :encrypted_key
    attr_accessor :cek
    
    
    def encrypt(key, alg, enc)
      header[:alg] = alg
      header[:enc] = enc
      cipher = generate_cipher(enc,true)
      cipher_text = cipher.update(data)
      cipher_text << cipher.final
      header[:iv] = cipher.iv
      encrypted_key = encrypt_cek(key,cipher,alg)
      [
        header.to_json,
        encrypted_key,
        cipher_text,
        iv || ""
      ].collect do |segment|
        UrlSafeBase64.encode64 segment
      end.join('.')
    end
    
    def decrypt(key)
      alg = header[:enc]
      cek = decrypt_cek(key, encrypted_key,alg)
      cipher = generate_cipher(alg,false, cek, header[:iv])
      data = cipher.update(Base64.strict_decode64(edata))
      data << cipher.final
      data
    end
    
    def self.decode(jwe_string)
      raise InvalidFormat.new('Invalid JWT Format. JWT should include 2 dots.') unless jwe_string.count('.') == 3
      header, encrypted_key, cipher_text, iv = jwe_string.split('.', 3).collect do |segment|
        UrlSafeBase64.decode64 segment.to_s
      end
      
      jwe = JWE.new
      jwe.header = JSON.parse(header)
      jwe.cipher_text = cipher_text
      jwe.encrypted_key
      jwe.iv = iv
      jwe
      
    end
    
    
    def self.encrypt(key, alg,enc, ptext)   
      jwe = JWE.new
      jwe.data = ptext
      jwe.encrypt(key,alg,enc)
    end

    private 
    
    
    def gcm?(alg)
      
    end
    
    def cbc?(alg)
      
    end

    
    
    def generate_cipher(alg, encrypt, key=nil, iv=nil)
      cipher = OpenSSL::Cipher::Cipher.new(cipher_name)
      if encrypt 
        cipher.encrypt 
      else
        cipher.decrypt
      end
      key ||= OpenSSL::Random.random_bytes(cipher.key_len)
      cipher.key = key
      iv ||= OpenSSL::Random.random_bytes(cipher.iv_len)
      cipher.iv = iv
      cipher
    end
    
    
    def encrypt_cek(key, cipher)
      key.public_encrypt(cipher.key)
    end
  
  
    def decrypt_cek(key,encrypted_cek)
      key.public_decrypt(encrypted_key)
    end
    
  end
end