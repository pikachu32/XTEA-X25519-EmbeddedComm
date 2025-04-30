import os

#curba 25519 : y^2 = x^3 +486662 * x^2 + x
#peste un corp finit p = 2^255 - 19

P=2**255 - 19
A24=121665 #(486662-2)/4   - factor pt optimizare calcule?
G=9 #punctul generator

#swap conditionat
def cswap(swap, x, y):            
    dummy = swap * (x - y) % P    # timing attacks -> nu folosim if-uri 
    x = (x - dummy) % P           # %P -> ne asiguram ca operatiile raman in limitele definite de curba
    y = (y + dummy) % P
    return x, y

#scalarea punctului u pe curba
def montgomery_ladder(k, u):              # u = G
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1    # (x2, z2) = (1, 0) - punctul de start
    swap = 0                              # (x3, z3) = (u, 1) - punctul de initiere pt scalare                                                               
    
#pt fiecare bit din cheia privata(de la msb la lsb) se aplica operatii pt a calcula o putere scalata a lui G
    for i in reversed(range(255)):          
        bit = (k >> i) & 1                  
        swap ^= bit
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = bit

#Formula pentru dublarea unui punct pe curba Montgomery: 
# z′=(𝐴^2−𝐵^2)*(𝐴^2+𝐴24*(𝐴^2−𝐵^2))
# x′=𝐴^2⋅𝐵^2
        A = (x2 + z2) % P #A=x2 + z2
        AA = (A * A) % P  #A^2
        B = (x2 - z2) % P #B^2 = x2 - z2
        BB = (B * B) % P  #B^2
        E = AA - BB       #A^2 - B^2


        C = (x3 + z3) % P  #C = C = x3 + z3
        D = (x3 - z3) % P  #D = x3 - z3
        DA = (D * A) % P   #D*A
        CB = (C * B) % P   #C*B
        x3 = ((DA + CB) ** 2) % P #(D*A + C*B)^2
        z3 = (u * ((DA - CB) ** 2)) % P #G*(D*A - C*B)^2
        x2 = (AA * BB) % P #𝐴^2*𝐵^2
        z2 = (E * (AA + A24 * E)) % P #(𝐴^2−𝐵^2)*(𝐴^2+𝐴24*(𝐴^2−𝐵^2))

    return (x2 * pow(z2, P-2, P)) % P


def generate_private_key():
    private_key = int.from_bytes(os.urandom(32), 'little')
    private_key &= (1 << 254) - 8  
    private_key |= 1 << 254
    return private_key

def generate_public_key(private_key):python
    return montgomery_ladder(private_key, G)

alice_private = generate_private_key()
print("alice private key: ",alice_private)
alice_public = generate_public_key(alice_private)
print("alice public key: ",alice_public)

bob_private = generate_private_key()
print("bob private key: ", bob_private)
bob_public = generate_public_key(bob_private)
print("bob public key: ", bob_public)


alice_shared_secret = montgomery_ladder(alice_private, bob_public)
bob_shared_secret = montgomery_ladder(bob_private, alice_public)

print("cheia comuna gaside de alice: ", alice_shared_secret)
print("cheia comuna gaside de bob  : ", bob_shared_secret)
assert alice_shared_secret == bob_shared_secret, "Cheile comune nu coincid!"