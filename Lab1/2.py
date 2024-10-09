def keymsg(jk,leng):
    key=jk
    while len(key)<leng:
        key+=jk
    key=key[:leng]
    return key 

def encrypt(message,key,autokey):
    message=message.lower()
    li=[]
    encmsg=""
    for i in range(len(message)):
        num=ord(message[i])-ord('a')
        num1=ord(key[i])-ord('a')
        numch=chr(((num+num1)%26)+ord('a'))
        encmsg+=numch
    li.append(encmsg)
    encmsg=""
    for i in range(len(message)):
        num=ord(message[i])-ord('a')
        num1=ord(autokey[i])-ord('a')
        numch=chr(((num+num1)%26)+ord('a'))
        encmsg+=numch
    li.append(encmsg)
    return li

def decrypt(message,key):
    message=message.lower()
    encmsg=""
    for i in range(len(message)):
        numch=chr(((ord(message[i])-ord(key[i]))%26)+ord('a'))
        encmsg+=numch
    return encmsg
def autodec(message,key):
    decmsg=""
    akey=""
    akey+=chr(key+ord('a'))
    for i in range(len(message)):
        num=ord(message[i])-ord('a')
        num1=ord(akey[i])-ord('a')
        numch=chr(((num-num1)%26)+ord('a'))
        decmsg+=numch
        akey+=numch
    return decmsg

message="the house is being sold tonight"
message=message.replace(" ","")
key="dollars"
autkey=chr(7+ord('a'))
autkey+=message[:len(message)-1]
encmsg=encrypt(message,keymsg(key.lower(),len(message)),autkey)
vigenc,autoenc=encmsg
print(autodec(autoenc,7))
