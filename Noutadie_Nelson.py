# -*- coding: utf-8 -*-

#@author: Mr ABBAS-TURKI ->> NOUTADIE Nelson
import hashlib
import binascii
import random
import os
import time

def home_mod_expnoent(x,y,n): #exponentiation modulaire
       R1 = 1
       R2 = x
       while y > 0:
           if y % 2 == 1:
               R1 = (R1 * R2) % n
           R2 = (R2 * R2) % n
           y = y // 2
       return R1

def home_mod_exponoent_trace(x,y,n): #exponentiation modulaire avec trace
       R1 = 1
       R2 = x
       count = 0 #compteur pour le nombre de multiplications coditionnelles
       while y > 0:
           if y % 2 == 1:
               R1 = (R1 * R2) % n
               count += 1
               print("multiplication  numero ",count)
           R2 = (R2 * R2) % n
           y = y // 2
       return R1

def home_ext_euclide(y,b): #algorithme d'euclide étendu pour la recherche de l'exposant secret
    (r, nouveau_r, t ,nouveau_t) = (y, b, 0, 1)
    while nouveau_r>1 :
        quotient = r//nouveau_r
        (r, nouveau_r) = (nouveau_r, r - quotient*nouveau_r)
        (t, nouveau_t) = (nouveau_t, t - quotient*nouveau_t)
    return nouveau_t%y

def home_reste_chinois(c,d,p,q): # Theoreme des restes chinois  
#calcul secret avec le theoreme des restes chinois   
    n = p*q
    invq=home_ext_euclide(q,p)
    dq = d%(q-1)
    dp = d%(p-1)
#calcul  a la reception du message
    mp=home_mod_expnoent(c,dp,p)
    mq=home_mod_expnoent(c,dq,q)
    h = ((mq-mp)*invq)%p
    m=(mq+h*q)%n
    return m

def home_bourage_chif(message, e, n):
    m_int = home_string_to_int(message) #message en entier
    m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big') 
    k = (n.bit_length() + 7) // 8  #taille du bloc de message en oc
    jmax = k // 2  # maximum message block size
    
    #decoupage du message en blocs
    blocks = [m_bytes[i:i+jmax] for i in range(0, len(m_bytes), jmax)]
    encrypted_blocks = []
    
    for block in blocks:
        # calcul de la taille du bloc
        j = len(block)
        padding_length = k - j - 3  
        x = bytes([random.randint(1, 255) for _ in range(padding_length)])   
        padded_block = b'\x00\x02' + x + b'\x00' + block
        # converssion en entien des octets
        padded_int = int.from_bytes(padded_block, 'big')
        # chiffrement avec RSA des différents blocs
        encrypted_block = home_mod_expnoent(padded_int, e, n)
        encrypted_blocks.append(encrypted_block)  
    return encrypted_blocks

def home_bourage_dechif(encrypted_blocks, d, n):
    decrypted_blocks = []
    k = (n.bit_length() + 7) // 8  # taille du bloc de message en octets
    
    for block in encrypted_blocks:
        # dechiffrement du bloc avec RA 
        decrypted_int = home_mod_expnoent(block, d, n)
        decrypted_bytes = decrypted_int.to_bytes(k, 'big')
        
        #retire le bourage 
        try:
            # trouve la position du separateur 00
            separator_pos = decrypted_bytes.index(b'\x00', 2)
            message_block = decrypted_bytes[separator_pos+1:]
            decrypted_blocks.append(message_block)
        except ValueError:
            raise ValueError("pas juste ceci")
    
    # fusionne les blocs decryptes
    full_message = b''.join(decrypted_blocks)
    
    # Convertit le message en entier
    full_message_int = int.from_bytes(full_message, 'big')
    return home_int_to_string(full_message_int)
 
def home_pgcd(a,b): #recherche du pgcd
    if(b==0): 
        return a 
    else: 
        return home_pgcd(b,a%b)

def home_string_to_int(x): # pour transformer un string en int
    z=0
    for i in reversed(range(len(x))):
        z=int(ord(x[i]))*pow(2,(8*i))+z
    return(z)

def home_int_to_string(x): # pour transformer un int en string
    txt=''
    res1=x
    while res1>0:
        res=res1%(pow(2,8))
        res1=(res1-res)//(pow(2,8))
        txt=txt+chr(res)
    return txt

def mot10char(): #entrer le secret
    secret=input("donner un secret de 47 caracteres au maximum : ")
    while (len(secret)>45):
        secret=input("Ahaha c'est une erreur, Insere au max 45 caracteres : ")
    return(secret)
    

#voici les elements de la cle d'Alice
x1a=201962143321639545209409406704828093201939692627062315953551
#x1a=2010942103422233250095259520183 #p
x2a=325555563295926616694454767283405847504844114738007849328121
#x2a=3503815992030544427564583819137 #q
na=x1a*x2a
phia=((x1a-1)*(x2a-1))//home_pgcd(x1a-1,x2a-1)
ea=17
da=home_ext_euclide(phia,ea)

#voici les elements de la cle de bob
x1b=765691443508358410243521431812663525934506973177182620044939
#x1b=9434659759111223227678316435911 #p
x2b=328823553170781077806504786594394260075651594888792770517243
#x2b=8842546075387759637728590482297 #q
nb=x1b*x2b
phib=((x1b-1)*(x2b-1))//home_pgcd(x1b-1,x2b-1)
eb=23
db=home_ext_euclide(phib,eb)

print("*******************************************************************Utilisation du RSA*******************************************************************")


print("Vous etes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre cle publique que tout le monde a le droit de consulter")
print("n =",nb)
print("exposant :",eb)
print("voici votre precieux secret")
print("d =",db)
print("*********************************************************************************************************************************************************************************************************")
print("Voici aussi la cle publique d'Alice que tout le monde peut conslter")
print("n =",na)
print("exposent :",ea)
print("*********************************************************************************************************************************************************************************************************")
print("il est temps de lui envoyer votre secret ")
print("*********************************************************************************************************************************************************************************************************")
x=input("appuyer sur entrer")
secret=mot10char()
print("*********************************************************************************************************************************************************************************************************")
print("voici la version en nombre decimal de ",secret," : ")
num_sec=home_string_to_int(secret)
print(num_sec)
print("voici le message chiffre avec la publique d'Alice : ")
#chif=home_mod_expnoent(num_sec, ea, na)
chif=home_mod_exponoent_trace(num_sec, ea, na)
print(chif)
print("*********************************************************************************************************************************************************************************************************")
print("On n'utilise plus la fonction de hashage MD5 pour obtenir le hash du message ",secret ," mais SHA256")
#Bhachis0=hashlib.md5(secret.encode(encoding='UTF-8',errors='strict')).digest() #MD5 du message
Bhachis0=hashlib.sha256(secret.encode(encoding='UTF-8',errors='strict')).digest() #sha256 du message

print("voici le hash en nombre decimal ")
Bhachis1=binascii.b2a_uu(Bhachis0)
Bhachis2=Bhachis1.decode() #en string
Bhachis3=home_string_to_int(Bhachis2)
print(Bhachis3)
print("voici la signature avec la cle privee de Bob du hachis")
#signe=home_mod_expnoent(Bhachis3, db, nb)
signe=home_mod_exponoent_trace(Bhachis3, db, nb)
print(signe)
print("*********************************************************************************************************************************************************************************************************")
print("Bob envoie \n \t 1-le message chiffre avec la cle public d'Alice \n",chif,"\n \t 2-et le hash signe \n",signe)
print("*********************************************************************************************************************************************************************************************************")
x=input("appuyer sur entrer")
print("*********************************************************************************************************************************************************************************************************")
print("Alice dechiffre le message chiffre \n",chif,"\nce qui donne ")
#dechif=home_int_to_string(home_mod_expnoent(chif, da, na))
#dechif=home_int_to_string(home_mod_exponoent_trace(chif, da, na))
dechif=home_int_to_string(home_reste_chinois(chif, da, x1a, x2a)) #CRT pour recontruire le message
print(dechif)
print("*********************************************************************************************************************************************************************************************************")
print("Alice dechiffre la signature de Bob \n",signe,"\n ce qui donne  en decimal")
#designe=home_mod_expnoent(signe, eb, nb)
designe=home_mod_exponoent_trace(signe, eb, nb)
print(designe)
print("Alice verifie si elle obtient la meme chose avec le hash de ",dechif)
#Ahachis0=hashlib.md5(dechif.encode(encoding='UTF-8',errors='strict')).digest()
Ahachis0=hashlib.sha256(dechif.encode(encoding='UTF-8',errors='strict')).digest() #sha256 du message
Ahachis1=binascii.b2a_uu(Ahachis0)
Ahachis2=Ahachis1.decode()
Ahachis3=home_string_to_int(Ahachis2)
print(Ahachis3)
print("La difference =",Ahachis3-designe)
if (Ahachis3-designe==0):
    print("Alice : Bob m'a envoye : ",dechif)
else:
    print("oups")

time.sleep(5)

print("*******************************************************************Utilisation du bourage*******************************************************************")
print("Je suis Bob , je vais envoyer un message a Alice")
Z=input("appuyer sur entrer")
secret2=mot10char()
print("*********************************************************************************************************************************************************************************************************")
chif2=home_bourage_chif(secret2,ea,na)
print("voici le message chiffre avec la publique d'Alice : ")
print(chif2)
print("*********************************************************************************************************************************************************************************************************")
print("nous allons hasher le message avec SHA256")
Bhachis0=hashlib.sha256(secret2.encode(encoding='UTF-8',errors='strict')).digest() #sha256 du message
print("voici le hash en nombre decimal ")
print("voici le hash en nombre decimal ")
Bhachis1=binascii.b2a_uu(Bhachis0)
Bhachis2=Bhachis1.decode() #en string
Bhachis3=home_string_to_int(Bhachis2)
print(Bhachis3)

print("voic la signature avec ma cle prviee")
signe2=home_mod_expnoent(Bhachis3, db, nb)
print(signe2)
print("*********************************************************************************************************************************************************************************************************")
print("Bon a Alice j'envoie \n \t mon message chiffre avec la cle public d'Alice \n",chif2,"\n \t et mon hash signe \n",signe2)

x=input("appuyer sur entrer")
print("*********************************************************************************************************************************************************************************************************")
print("Je suis Alice, je vais dechiffrer le message de Bob")
print("*********************************************************************************************************************************************************************************************************")

dechif2 = home_bourage_dechif(chif2, da, na) #dechiffrement du message avec le bourage
print("voici le message dechiffre que j'ai recu: ",dechif2)

print("*********************************************************************************************************************************************************************************************************")
print("Je vais dechiffrer la signature de Bob")
print("*********************************************************************************************************************************************************************************************************")
designe2=home_mod_expnoent(signe2, eb, nb)
print(designe2)
print("Verification si le hash de ",dechif2," est le meme que la signature de Bob")
Ahachis0=hashlib.sha256(dechif2.encode(encoding='UTF-8',errors='strict')).digest() #sha256 du message
Ahachis1=binascii.b2a_uu(Ahachis0)
Ahachis2=Ahachis1.decode()
Ahachis3=home_string_to_int(Ahachis2)
print(Ahachis3)
print("La difference =",Ahachis3-designe2)
if (Ahachis3-designe2==0):
    print("Bon m'a envoye : ",dechif2)
else:
    print("Ah non jai pas recu le bon message")