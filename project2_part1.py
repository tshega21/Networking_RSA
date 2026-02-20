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
        p = getPrime(512, rand)
        q = getPrime(512)
    
    totient_n = (p-1)*(q-1)
    n = p*q # field n
    
    # find multiplicative inverse of e relative to totient_n
    d = pow(e,-1,totient_n)
    
    print("private key:",d)
    #returns n, largest value that can be stored using public/private key pair and generated private key
    return n, d

def main():
    n,d = key_generation(65537)
    
    
if __name__ == "__main__":
    main()
    
    