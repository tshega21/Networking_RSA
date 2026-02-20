import random
from time import time
from Crypto.Util.number import getPrime
import math
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from numpy.polynomial import Polynomial


def key_generation(e):
    """
    Args:
        e (int) - public key
    """
   
    #Should we seed this prime or not? 
    #Should we find our own prime according to what we discussed in class or is getPrime okay?
   
    p = getPrime(512)
    q = getPrime(512)

    totient_n = (p-1)*(q-1)
    
    
    while (math.gcd(totient_n,e)!= 1):
        p = getPrime(512)
        q = getPrime(512)
    
    totient_n = (p-1)*(q-1)
    n = p*q # field n
    
    # find multiplicative inverse of e relative to totient_n
    d = pow(e,-1,totient_n)
    
    #returns n, largest value that can be stored using public/private key pair and generated private key
    return n, d

def encryption(m, e, n):
    c = pow(m,e,n)
    return c
def decryption(c, d, n):
    m = pow(c,d,n)
    return m
def main():
    e = 65537
    n,d = key_generation(e)
    messages = [34,30]
    run_times = []
    decrypted_messages = []
    for message in messages:
        
        t_0 = time()

        c = encryption(message,e,n)
        print("cipher text ", c)
        d_plaintext = decryption(c,d,n)
        print("decrypted plaintext ", d_plaintext)
        
        final_time = time()-t_0
        run_times.append(final_time)
        decrypted_messages.append(d_plaintext)
        print("RSA runtime for message ",message, " : ",final_time )
    
    
    
if __name__ == "__main__":
    main()
    
    