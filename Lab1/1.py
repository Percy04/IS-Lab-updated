def mod_inverse(a, m):
    for i in range(m):
        if (a*i)%m==1:
            return i
    return None

def encrypt(message, key,type):
    message = message.replace(" ", "").lower()
    encrypted_message = []

    for char in message:
        if char.isalpha():  
            num = ord(char) - ord('a')
            
            if type=='add':
                num = (num + key) % 26
            elif type=='mul':
                num = (num * key) % 26
            
            encrypted_char = chr(num + ord('a'))    
            encrypted_message.append(encrypted_char)
        else:
            encrypted_message.append(char)
    
    return ''.join(encrypted_message)

def decrypt(encrypted_message, key,type):
    decrypted_message = []

    for char in encrypted_message:
        if char.isalpha():  
            num = ord(char) - ord('a')
            if type=='add':
                num = (num - key) % 26
            elif type=='mul':
                
                inverse_key = mod_inverse(key, 26)
                num = (num * inverse_key) % 26
            decrypted_char = chr(num + ord('a'))
            decrypted_message.append(decrypted_char)
        else:
            decrypted_message.append(char)
    
    return ''.join(decrypted_message)

def affencryption(message,k1,k2):
    message = message.replace(" ", "").lower()
    encmsg=""
    for c in message:
        num =ord(c) - ord('a')
        num= (k1*num+k2)%26
        numch=chr(num+ord('a'))
        encmsg+=numch
        
    return encmsg


def affdec(message,k1,k2):
    message = message.replace(" ", "").lower()
    encmsg=""
    n=mod_inverse(k1,26)
    for c in message:
        num = ord(c)-ord('a')
        num=(n*(num-k2))%26
        numch=chr(num+ord('a'))
        encmsg+=numch
    return encmsg
        
message = "I am learning information security"
key = 20
encrypted_message = affencryption(message, 15,20)
print("Encrypted Message:",encrypted_message)

decrypted_message = affdec(encrypted_message, 15,20)
print(f"Decrypted Message: {decrypted_message}")

print("Multiplicative Encryption:",encrypt(message,15,'mul'))