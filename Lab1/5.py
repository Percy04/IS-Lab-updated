def findkey(encmsg,pt):
    key=ord(encmsg[0])-ord(pt[0])
    return key%26

def findmsg(encmsg,key):
    pt=""
    for i in encmsg:
        num=ord(i)-ord('a')
        num=(num-key)%26
        pt+=chr(num+ord('a'))
    return pt
        

encmsg="ciw"
pt="yes"
newencmsg="xviewywi"
print(findkey(encmsg,pt),findmsg(newencmsg,4))
