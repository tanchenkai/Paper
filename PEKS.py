#! /usr/bin/env python3
import unittest
import hashlib
from pypbc import *
import os,os.path
import base64
from Cryptodome import Random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Cryptodome.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
import time

Hash1 = hashlib.sha256
Hash2 = hashlib.sha256



def KeyGen(q,r):
    print("\n 输入qbits=1024, rbits=160")
    params = Parameters(qbits=q,rbits=r)#生成双线性配对
    pairing = Pairing(params)
    g = Element.random(pairing, G2)
    print("\n得到系统参数pairing",str(params))
    print("\n得到系统生成元 P=",str(g))
    return [params, g]

def KeyGen1(paramas,g):
    pairing = Pairing(params)
    sk = Element.random(pairing, Zr)
    pk = Element(pairing, G2, value = g ** sk)
    return [sk, pk]

def Trapdoor(params,g, sk, word):
    pairing = Pairing(params)
    #Hash1(str(word).encode('utf-8')).hexdigest())
    hash_value = Element.from_hash(pairing, Zr,word)
    print("\n1.将关键字w通过哈希算法映射到循环群Z上")
    print("\nH_1(w)=Element.from_hash(pairing, Zr,word)=\n")
    print(str(hash_value))
    print("\n2.计算车辆私钥H_1(w)+Sk_s:")
    temp=Element.__add__(hash_value,sk)
    print(str(temp))
    print("\n3.计算 temp=1/(H_1(w)+Sk_s):")
    temp=Element.__invert__(temp)
    print(str(temp))
    temp = Element(pairing, G2, value = g**temp)
    print("\n4.计算 T_w=Element(pairing, G1, value = P**temp)得到T_w属于循环群G1:")
    print(str(temp))
    return temp
    
def Trapdoor1(params,g, sk, word):
    pairing = Pairing(params)
    #Hash1(str(word).encode('utf-8')).hexdigest())
    hash_value = Element.from_hash(pairing, Zr,word)
    print("\n5.输入相同的Keyword可以得到T_w'=")
    temp=Element.__add__(hash_value,sk)
    temp=Element.__invert__(temp)
    temp = Element(pairing, G2, value = g**temp)
    print(str(temp))
    return temp
    
def Trapdoor2(params,g, sk, word):
    pairing = Pairing(params)
    #Hash1(str(word).encode('utf-8')).hexdigest())
    hash_value = Element.from_hash(pairing, Zr,word)
    temp=Element.__add__(hash_value,sk)
    temp=Element.__invert__(temp)
    temp = Element(pairing, G2, value = g**temp)
    print(str(temp))
    return temp


def PEKS(params, g, pk_s,pk_c, word):
    pairing = Pairing(params)
    print("\n1.随机在循环群Z上选择r1=")
    r1=Element.random(pairing, Zr)
    r2=Element.random(pairing, Zr)
    print(str(r1))
    print("\n随机在循环群Z上选择r2=")
    print(str(r2))
    hr = pk_s ** r1
    hash_value = Element.from_hash(pairing, Zr,word)
    A1= (g**hash_value)**r1
    A=Element.__add__(A1,hr)
    print("\n2.计算A= r1H_1(w)P + r1pk_s")
    print(str(A))
    B=g ** r2
    print("\n3.计算B=  r2P ")
    V=pairing.apply(g ** r1+A**r2, pk_c)
    V=Hash2(str(V).encode('utf-8')).hexdigest()
    print("\n4 计算V==H2(eˆ(r1P + r2A, pk_c ))")
    print(str(V))
    return [A,B,V]



def Test(params, pk_s, sk_c, A, B, V, T_w):
    pairing = Pairing(params)

    temp=A**sk_c

    temp2=Element.__add__(T_w,B)

    V1=pairing.apply(temp,temp2)
    V1=Hash2(str(V1).encode('utf-8')).hexdigest()
    print("\nH2(eˆ(yA, T_w+ B))=V1=")
    print(str(V1))
    return V1==V


def Keysave(name,key,key_type):
    counter = 1
    file_name = name
    file_out = open(file_name.format(counter), "wb")
    key=str(key)
    file_out.write(key.encode())
    print("\n密钥%s已经保存在文件%s"%(key_type,file_name))
    file_out.close()


#RSA加密
def rsa_encrypt_binfile(file_path,save_path,pub_key):
    '''
    rsa 加密二进制文件
    :param file_path:需要加密文件路径
    :param save_path:加密之后存放的文件路径
    :param pub_key:公钥
    '''
    with open(file_path, 'rb') as f:
        message = f.read()
    length = len(message)
    default_length = 117  # 1024/8 - 11 1024为密钥长度
    rsakey = RSA.importKey(pub_key)
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    # 不需要切分
    result = []
    if length <= default_length:
        result.append(base64.b64encode(cipher.encrypt(message)))

    # 需要切分
    offset = 0
    while length - offset > 0:
        if length - offset > default_length:
            result.append(base64.b64encode(cipher.encrypt(message[offset:offset+default_length])))
        else:
            result.append(base64.b64encode(cipher.encrypt(message[offset:])))
        offset += default_length

    with open(save_path,"ab+") as w:
        for ciphertext in result:
            ciphertext += b"\n"
            w.write(ciphertext)


def rsa_decrypt_binfile(file_path,save_path,priv_key):
    '''
    rsa 解密二进制文件
    :file_path:需要解密的文件路径
    :save_path:解密之后存放的文件路径
    :priv_key:私钥
    '''
    with open(file_path, "rb") as f:
        line = f.readline()
        while line:
            message = base64.b64decode(line.strip(b"\n"))
            rsakey = RSA.importKey(priv_key)
            cipher = Cipher_pkcs1_v1_5.new(rsakey)
            plaintext = cipher.decrypt(message, random_generator)
            with open(save_path, 'ab+') as w: #追加写入
                w.write(plaintext)
            line = f.readline()




if __name__ == '__main__':
    print("A.KeyGen\n")
    print("\n 1.生成参数、生成元")
    [params, g] = KeyGen(1024,160 )
    print("\n 2.生成发送者的公私钥")
    [sk_s,pk_s]=KeyGen1(params, g)
    print("\n 计算发送者私钥 Sk_s=Element.random(pairing, Zr)=",str(sk_s))
    print("\n 计算发送者公钥 Pk_s=Element(pairing, G2, value = g ** sk)",str(pk_s))
    
    print("\n 3.生成服务器的公私钥")
    [sk_c,pk_c]=KeyGen1(params, g)#生成服务器公私钥
    print("\n 计算服务器私钥 Sk_c=",str(sk_c))
    print("\n 计算发送者公钥 Pk_c=",str(pk_c))
    

    print("\n 4.保存用户密钥")

    Keysave("./keys/sender_private_key_{0}.pem",sk_s,"sender private key")
    Keysave("./keys/sender_pbulic_key_{0}.pem", pk_s,"sender public key")

    print("\n 5.保存服务器密钥")
    Keysave("./keys/server_private_key_{0}.pem" ,sk_c,"server private key")
    Keysave("./keys/server_pbulic_key_{0}.pem", pk_c,"server public key")


    print("\n\n\n")


    print("\nB.打开消息message,然后发送者通过加密算法对消息进行加密")
    message = open("message.txt","r")
    print("\n加密前的消息为:")
    print(message.read())
    print("\n生成RSA加密算法1024位的公私钥并且保存，用于加密解密消息")

    random_generator = Random.new().read
#     # rsa算法生成实例
    rsa = RSA.generate(1024, random_generator)
    private_pem = str(rsa.exportKey(), encoding="utf-8")
    with open("./keys/client-private.pem", "w") as f:
        f.write(private_pem)
    public_pem = str(rsa.publickey().exportKey(), encoding="utf-8")
    with open("client-public.pem", "w") as f:
        f.write(public_pem)
    print("\n对消息进行加密先压缩后加密")
#     #删除重复文件
    if os.path.exists("ciphertext.txt"):
        os.remove("ciphertext.txt")
    if os.path.exists("decrypt_message.txt"):
        os.remove("decrypt_message.txt")
    rsa_encrypt_binfile("message.txt","ciphertext.txt",public_pem)
    ciphertext=open("ciphertext.txt","r")
    print("\n加密后的消息为:")
    print(ciphertext.read())

    print("\n通过私钥可以解密加密文件")
    rsa_decrypt_binfile("ciphertext.txt","decrypt_message.txt", private_pem)
    decrypt_message=open("decrypt_message.txt","r")
    print("\n解密后的消息为:")
    print(decrypt_message.read())


    print("\nC.输入私钥和关键字 w=‘GQWRG’，车辆 S 计算对应的陷门 Tw")
    t_w=Trapdoor(params,g, sk_s, "GQWRG")
    
    
    print("\nD.输入车辆公钥Pk_s、服务器公钥Pk_c、关键字w，车辆S随机选择r1,r2 ∈Zq。 车辆 S 计算 (A,B,V)。")
    [A,B,V]=PEKS(params, g, pk_s,pk_c, "GQWRG")
    
    print("\nE.通过链接PEKS和加密消息计算加密文档:")
    
    secrect=ciphertext.read()+str(A)+str(B)+str(V)
    print(secrect)
    
    print("\nE.得到加密文档的签名为:")
    Hashi=Trapdoor2(params,g, sk_s, secrect)
    
    
    
    print("\nF.输入车辆公钥 Pk_s、服务器私钥 Sk_c、(A,B,V)、陷门 Tw。然后测试 H2(eˆ(yA, Tw+ B)) = V 是否成立。")
#    print("ooooyeeee",A,B,V)
    assert(Test(params,pk_s, sk_c, A, B, V, t_w))

#    print("yeeees")
#    print("打开本地的关键字文档")
#    keywords = open("key.txt","r")
#    print(keywords.read())
#    f1 = open(tf,"a+")
#    trapdoor = open("trapdoor_key.txt","a+")


    #PEKS
#    cipher = PEKS(params, g, pk_s, "GQW")
#    print(cipher)
    #test
#    assert(Test(params, pk_s, cipher, td))

    #td = Trapdoor(params, sk_s, "GQK")

    #assert(not Test(params, pk_s, cipher, td))


