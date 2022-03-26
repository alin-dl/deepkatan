# -*- coding: utf-8 -*-
"""
Created on Wed Sep  8 17:16:02 2021

@author: L
"""


#!/usr/bin/env python
import numpy as np 
from os import urandom
import time
def WORD_SIZE():
    return(32)

IR = (
    1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0,
    1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0,
    0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
    0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1,
    1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1,
    1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1,
    1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1,
    0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
    1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0,
    0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1,
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0,
)  


def tup2bits(tup, bitlength):
    bits = []
    for i in range(len(tup)):
        temp = []
        s = tup[len(tup)-1-i]
        s = np.copy(s)
        for j in range(int(bitlength/len(tup))):
            temp.append(s&1)
            s >>= 1
        bits += temp
    bits = bits[::-1]
    return bits
        

def num2bits(num, bitlength):
    bits = []
    for i in range(bitlength):
        bits.append(num & 1)
        num >>= 1
    return bits



def bits2num(bits):
    num = 0
    for i, x in enumerate(bits):
        x = x.astype(np.int64)
        num += (x << i)
    return num



def lfsr(iv,nr):
    state = tup2bits(iv, 80)
    for i in range(nr * 2):
        yield state[0]
        state.append(state[0] ^ state[19] ^ state[30] ^ state[67])
        state.pop(0)


class KATAN():
    def __init__(self, master_key=0, version=32, nr=254):
        assert version in (32, 48, 64)
        self.version = version
        self.nr = nr 

        if 32 == self.version:
            self.LEN_L1 = 13
            self.LEN_L2 = 19
            self.X = (None, 12, 7, 8, 5, 3)  # starting from 1
            self.Y = (None, 18, 7, 12, 10, 8, 3)
        elif 48 == self.version:
            self.LEN_L1 = 19
            self.LEN_L2 = 29
            self.X = (None, 18, 12, 15, 7, 6)
            self.Y = (None, 28, 19, 21, 13, 15, 6)
        else:
            self.LEN_L1 = 25
            self.LEN_L2 = 39
            self.X = (None, 24, 15, 20, 11, 9)
            self.Y = (None, 38, 25, 33, 21, 14, 9)

        self.change_key(master_key)

    def change_key(self, master_key):
        self.key = []
        stream = lfsr(master_key,self.nr)
        for i in range(self.nr * 2):
            self.key.append(stream.__next__())
        return self.key    

    def one_round_enc(self, round):
        k_a = self.key[2 * round]
        k_b = self.key[2 * round + 1]

        self.f_a = self.L1[self.X[1]] ^ self.L1[self.X[2]]  \
                ^ (self.L1[self.X[3]] & self.L1[self.X[4]]) \
                ^ k_a
        if IR[round]:
            self.f_a ^= self.L1[self.X[5]]

        self.f_b = self.L2[self.Y[1]] ^ self.L2[self.Y[2]]  \
                ^ (self.L2[self.Y[3]] & self.L2[self.Y[4]]) \
                ^ (self.L2[self.Y[5]] & self.L2[self.Y[6]]) \
                ^ k_b

        self.L1.pop()
        self.L1.insert(0, self.f_b)

        self.L2.pop()
        self.L2.insert(0, self.f_a)

    def enc(self, plaintext, from_round=0):
        self.to_round=self.nr-1
        self.plaintext_bits = num2bits(plaintext, self.version)
        self.L2 = self.plaintext_bits[:self.LEN_L2]
        self.L1 = self.plaintext_bits[self.LEN_L2:]

        for round in range(from_round, self.to_round + 1):
            self.one_round_enc(round)
            if self.version > 32:
                self.one_round_enc(round)
                if self.version > 48:
                    self.one_round_enc(round)
        return bits2num(self.L2 + self.L1)

    def one_round_dec(self, round):
        k_a = self.key[2 * round]
        k_b = self.key[2 * round + 1]

        self.f_a = self.L2[0] ^ self.L1[self.X[2] + 1]              \
                ^ (self.L1[self.X[3] + 1] & self.L1[self.X[4] + 1]) \
                ^ k_a
        if IR[round]:
            self.f_a ^= self.L1[self.X[5] + 1]

        self.f_b = self.L1[0] ^ self.L2[self.Y[2] + 1]              \
                ^ (self.L2[self.Y[3] + 1] & self.L2[self.Y[4] + 1]) \
                ^ (self.L2[self.Y[5] + 1] & self.L2[self.Y[6] + 1]) \
                ^ k_b

        self.L1.pop(0)
        self.L1.append(self.f_a)

        self.L2.pop(0)
        self.L2.append(self.f_b)

    def dec(self, ciphertext, to_round=0):
        self.from_round=self.nr-1
        self.ciphertext_bits = num2bits(ciphertext, self.version)
        self.L2 = self.ciphertext_bits[:self.LEN_L2]
        self.L1 = self.ciphertext_bits[self.LEN_L2:]

        for round in range(self.from_round, to_round -1, -1):
            self.one_round_dec(round)
            if self.version > 32:
                self.one_round_dec(round)
                if self.version > 48:
                    self.one_round_dec(round)
        return bits2num(self.L2 + self.L1)
  

def check_testvector():
    key = (0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)
    plaintext = (0x0)
    #ks = expand_key(key, 23)   
    myKATAN = KATAN(key, 32, 254)
    ct = myKATAN.enc(plaintext)
    pt = myKATAN.dec(ct)
    print(ct)
    print(pt)
    if (ct == (0x7e1ff945)):     
        print("Testvector verified.")     
        return(True)   
    else:     
        print("Testvector not verified.")     
        return(False)  
#check_testvector()
    
def convert_to_binary(arr, l):     
    X = np.zeros((l * WORD_SIZE(),len(arr[0])),dtype=np.uint8)     
    for i in range(l * WORD_SIZE()):         
        index = i // WORD_SIZE();         
        offset = WORD_SIZE() - (i % WORD_SIZE()) - 1         
        X[i] = (arr[index] >> offset) & 1    
    X = X.transpose()     
    return (X)

#Generate C_structure
def make_structure(n, nr, keys, diff=(0x61082200), weak_neutral_bits = [30, 29, 26, 14, 12]):
    num =32
    cta = [];
    ctb = [];
    for i in range(int(n)):
      plain0 = np.frombuffer(urandom(4*num),dtype=np.uint32);
      plain0 = np.copy(plain0)
      for j in weak_neutral_bits:
        d = 1 << j;
        plain0 = np.concatenate([plain0,plain0^d]);# Generate from weak neutral bit sets
      plain0 = np.copy(plain0&0xF78FF736^0x00300008)
      # Generate 32 plaintext registers
      p31 = np.copy(plain0&0x80000000)>>31;p30 = np.copy(plain0&0x40000000)>>30;p29 = np.copy(plain0&0x20000000)>>29;p28 = np.copy(plain0&0x10000000)>>28;
      p27 = np.copy(plain0&0x08000000)>>27;p26 = np.copy(plain0&0x04000000)>>26;p25 = np.copy(plain0&0x02000000)>>25;p24 = np.copy(plain0&0x01000000)>>24;
      p23 = np.copy(plain0&0x00800000)>>23;p22 = np.copy(plain0&0x00400000)>>22;p21 = np.copy(plain0&0x00200000)>>21;p20 = np.copy(plain0&0x00100000)>>20;
      p19 = np.copy(plain0&0x00080000)>>19;p18 = np.copy(plain0&0x00040000)>>18;p17 = np.copy(plain0&0x00020000)>>17;p16 = np.copy(plain0&0x00010000)>>16;
      p15 = np.copy(plain0&0x00008000)>>15;p14 = np.copy(plain0&0x00004000)>>14;p13 = np.copy(plain0&0x00002000)>>13;p12 = np.copy(plain0&0x00001000)>>12;
      p11 = np.copy(plain0&0x00000800)>>11;p10 = np.copy(plain0&0x00000400)>>10;p9 = np.copy(plain0&0x00000200)>>9;p8 = np.copy(plain0&0x00000100)>>8;
      p7 = np.copy(plain0&0x00000080)>>7;p6 = np.copy(plain0&0x00000040)>>6;p5 = np.copy(plain0&0x00000020)>>5;p4 = np.copy(plain0&0x00000010)>>4;
      p3 = np.copy(plain0&0x00000008)>>3;p2 = np.copy(plain0&0x00000004)>>2;p1 = np.copy(plain0&0x00000002)>>1;p0 = np.copy(plain0&0x00000001);
      # Generate key registers in conditions
      k0 = np.copy(keys[0]&0x8000)>>15;k1 = np.copy(keys[0]&0x4000)>>14;k2 = np.copy(keys[0]&0x2000)>>13;k3 = np.copy(keys[0]&0x1000)>>12;
      k4 = np.copy(keys[0]&0x0800)>>11;k5 = np.copy(keys[0]&0x0400)>>10;k6 = np.copy(keys[0]&0x0200)>>9;k7 = np.copy(keys[0]&0x0100)>>8;
      k8 = np.copy(keys[0]&0x0080)>>7;k9 = np.copy(keys[0]&0x0040)>>6;k10 = np.copy(keys[0]&0x0020)>>5;k11 = np.copy(keys[0]&0x0010)>>4;
      k12 = np.copy(keys[0]&0x0008)>>3;k13 = np.copy(keys[0]&0x0004)>>2;k14 = np.copy(keys[0]&0x0002)>>1;k15 = np.copy(keys[0]&0x0001);
      k16 = np.copy(keys[1]&0x8000)>>15;k17 = np.copy(keys[1]&0x4000)>>14;k18 = np.copy(keys[1]&0x2000)>>13;k19 = np.copy(keys[1]&0x1000)>>12;
      k20 = np.copy(keys[1]&0x0800)>>11;k21 = np.copy(keys[1]&0x0400)>>10;k22 = np.copy(keys[1]&0x0200)>>9;k23 = np.copy(keys[1]&0x0100)>>8;
      k24 = np.copy(keys[1]&0x0080)>>7;k25 = np.copy(keys[1]&0x0040)>>6;k26 = np.copy(keys[1]&0x0020)>>5;k27 = np.copy(keys[1]&0x0010)>>4;
      k28 = np.copy(keys[1]&0x0008)>>3;k29 = np.copy(keys[1]&0x0004)>>2;k30 = np.copy(keys[1]&0x0002)>>1;k31 = np.copy(keys[1]&0x0001);
      k32 = np.copy(keys[2]&0x8000)>>15;k33 = np.copy(keys[2]&0x4000)>>14;k34 = np.copy(keys[2]&0x2000)>>13;k35 = np.copy(keys[2]&0x1000)>>12;
      k36 = np.copy(keys[2]&0x0800)>>11;k37 = np.copy(keys[2]&0x0400)>>10;k38 = np.copy(keys[2]&0x0200)>>9;k39 = np.copy(keys[2]&0x0100)>>8;
      k40 = np.copy(keys[2]&0x0080)>>7;k41 = np.copy(keys[2]&0x0040)>>6;k42 = np.copy(keys[2]&0x0020)>>5;k43 = np.copy(keys[2]&0x0010)>>4;
      k44 = np.copy(keys[2]&0x0008)>>3;k45 = np.copy(keys[2]&0x0004)>>2;k46 = np.copy(keys[2]&0x0002)>>1;k47 = np.copy(keys[2]&0x0001);
      k48 = np.copy(keys[3]&0x8000)>>15;k49 = np.copy(keys[3]&0x4000)>>14;k50 = np.copy(keys[3]&0x2000)>>13;k51 = np.copy(keys[3]&0x1000)>>12;
      k52 = np.copy(keys[3]&0x0800)>>11;k53 = np.copy(keys[3]&0x0400)>>10;k54 = np.copy(keys[3]&0x0200)>>9;k55 = np.copy(keys[3]&0x0100)>>8;
      k56 = np.copy(keys[3]&0x0080)>>7;k57 = np.copy(keys[3]&0x0040)>>6;k58 = np.copy(keys[3]&0x0020)>>5;k59 = np.copy(keys[3]&0x0010)>>4;
      k60 = np.copy(keys[3]&0x0008)>>3;k61 = np.copy(keys[3]&0x0004)>>2;k62 = np.copy(keys[3]&0x0002)>>1;k63 = np.copy(keys[3]&0x0001);
      k64 = np.copy(keys[4]&0x8000)>>15;k65 = np.copy(keys[4]&0x4000)>>14;k66 = np.copy(keys[4]&0x2000)>>13;k67 = np.copy(keys[4]&0x1000)>>12;
      k68 = np.copy(keys[4]&0x0800)>>11;k69 = np.copy(keys[4]&0x0400)>>10;k70 = np.copy(keys[4]&0x0200)>>9;k71 = np.copy(keys[4]&0x0100)>>8;
      k72 = np.copy(keys[4]&0x0080)>>7;k73 = np.copy(keys[4]&0x0040)>>6;k74 = np.copy(keys[4]&0x0020)>>5;k75 = np.copy(keys[4]&0x0010)>>4;
      k76 = np.copy(keys[4]&0x0008)>>3;k77 = np.copy(keys[4]&0x0004)>>2;k78 = np.copy(keys[4]&0x0002)>>1;k79 = np.copy(keys[4]&0x0001);
      # Compute the plaintext and key of the condition
      p16=np.copy(p5^p10*p8^p6*p1^k5)#c(9,1)
      s13=np.copy(p18^p7^p12*p10^p8*p3^k1)
      p17=np.copy(p6^p11*p9^p7*p2^k3);#Additional conditions, s14=0
      s14=np.copy(p17^p6^p11*p9^p7*p2^k3)
      s15=np.copy(p16^p5^p10*p8^p6*p1^k5)
      s16=np.copy(p15^p4^p9*p7^p5*p0^k7);
      p25=np.copy(p20^p21*s13^s15*IR[6]^k12)#c(13,0)
      p19=np.copy(p24^p20*s14^s16*IR[7]^k14)#c(17,0)
      p28=np.copy(p23^p24*p21^p19*IR[3]^k6)#c(15,0)
      
      p1=np.copy(p21^s15^p12^p6*p4^p2*(p29^p24^p25*p22^p20*IR[2]^k4)^k13^k20)#c(24,0)

      l19=np.copy(p31^p26^p27*p24^p22*IR[0]^k0)
      l20=np.copy(p30^p25^p26*p23^p21*IR[1]^k2)
      l21=np.copy(p29^p24^p25*p22^p20*IR[2]^k4)
      l22=np.copy(p28^p23^p24*p21^p19*IR[3]^k6)
      l23=np.copy(p27^p22^p23*p20^s13*IR[4]^k8)
      l24=np.copy(p26^p21^p22*p19^s14*IR[5]^k10)
      l25=np.copy(p25^p20^p21*s13^s15*IR[6]^k12)
      l26=np.copy(p24^p19^p20*s14^s16*IR[7]^k14)
      s18=np.copy(p13^p2^p7*p5^p3*l20^k11);
      s19=np.copy(p12^p1^p6*p4^p2*l21^k13);
      s20=np.copy(p11^p0^p5*p3^p1*l22^k15);
      
      p31=np.copy(p10^(p26^p27*p24^p22*IR[0]^k0)^p4*p2^p0*l23^k17^1);#Additional conditions, s21=1
      s17=np.copy(p14^p3^p8*p6^p4*l19^k9);
      l19=np.copy(p31^p26^p27*p24^p22*IR[0]^k0)
      s21=np.copy(p10^l19^p4*p2^p0*l23^k17);
      s22=np.copy(p9^l20^p3*p1^l19*l24^k19);
      s23=np.copy(p8^l21^p2*p0^l20*l25^k21);
      s24=np.copy(p7^l22^p1*l19^l21*l26^k23);
      l27=np.copy(p23^s13^p19*s15^s17*IR[8]^k16)
      l28=np.copy(p22^s14^s13*s16^s18*IR[9]^k18)
      l29=np.copy(p21^s15^s14*s17^s19*IR[10]^k20)
      l30=np.copy(p20^s16^s15*s18^s20*IR[11]^k22)
      l31=np.copy(p19^s17^s16*s19^s21*IR[12]^k24)
      l32=np.copy(s13^s18^s17*s20^s22*IR[13]^k26)
      l33=np.copy(s14^s19^s18*s21^s23*IR[14]^k28)
      l34=np.copy(s15^s20^s19*s22^s24*IR[15]^k30)
      s25=np.copy(p6^l23^p0*l20^l22*l27^k25);
      s26=np.copy(p5^l24^l19*l21^l23*l28^k27);
      s27=np.copy(p4^l25^l20*l22^l24*l29^k29);
      s28=np.copy(p3^l26^l21*l23^l25*l30^k31);
      s29=np.copy(p2^l27^l22*l24^l26*l31^k33);
      s30=np.copy(p1^l28^l23*l25^l27*l32^k35);
      s31=np.copy(p0^l29^l24*l26^l28*l33^k37);
      s32=np.copy(l19^l30^l25*l27^l29*l34^k39);
      l35=np.copy(s16^s21^s20*s23^s25*IR[16]^k32)
      p14=np.copy(p3^p8*p6^p4*l19^k9^s22^s21*s24^s26*IR[17]^k34)#c(22,0)
      
      p13=np.copy(s14^s19^(p2^p7*p5^p3*l20^k11)*s21^s23*IR[14]^k28)
      
      p16=p16<<16;p17=p17<<17;p1=p1<<1;p31=p31<<31;p14=p14<<14
      p19=p19<<19;p25=p25<<25;p13=p13<<13;p28=p28<<28;
      # Reassign plaintext bits
      plain0 = np.copy(plain0&0x6DF49FFD^p1^p13^p14^p16^p17^p19^p25^p28^p31);
      
      plain1 = plain0 ^ diff
      myKATAN = KATAN(keys, 32, nr)
      ctdata0 = myKATAN.enc(plain0)
      ctdata1 = myKATAN.enc(plain1)
      ctdata = ctdata0^ctdata1
      #print(len(ctdata))
      cta+=[ctdata0] 
      ctb+=[ctdata1]
    return (cta,ctb)

# Decrypt the last 13 rounds
def dec_rounds(ctdata0,ctdata1,ck1):
    k = np.copy(ck1);
    k98=np.copy(k&0x8000)>>15;  
    k100=np.copy(k&0x4000)>>14;
    k102=np.copy(k&0x2000)>>13;
    k103=np.copy(k&0x1000)>>12;
    k104=np.copy(k&0x800)>>11;
    k105=np.copy(k&0x400)>>10;
    k106=np.copy(k&0x200)>>9;
    k107=np.copy(k&0x100)>>8;
    k108=np.copy(k&0x80)>>7;
    k109=np.copy(k&0x40)>>6;
    k110=np.copy(k&0x20)>>5;
    k111=np.copy(k&0x10)>>4;
    k112=np.copy(k&0x8)>>3;
    k113=np.copy(k&0x4)>>2;
    k114=np.copy(k&0x2)>>1;
    k115=np.copy(k&0x1);
    # Ciphertext ctdata0 register
    s58 = np.copy(ctdata0&0x80000000)>>31;s59 = np.copy(ctdata0&0x40000000)>>30;s60 = np.copy(ctdata0&0x20000000)>>29;s61 = np.copy(ctdata0&0x10000000)>>28;
    s62 = np.copy(ctdata0&0x08000000)>>27;s63 = np.copy(ctdata0&0x04000000)>>26;s64 = np.copy(ctdata0&0x02000000)>>25;s65 = np.copy(ctdata0&0x01000000)>>24;
    s66 = np.copy(ctdata0&0x00800000)>>23;s67 = np.copy(ctdata0&0x00400000)>>22;s68 = np.copy(ctdata0&0x00200000)>>21;s69 = np.copy(ctdata0&0x00100000)>>20;
    s70 = np.copy(ctdata0&0x00080000)>>19;l58 = np.copy(ctdata0&0x00040000)>>18;l59 = np.copy(ctdata0&0x00020000)>>17;l60 = np.copy(ctdata0&0x00010000)>>16;
    l61 = np.copy(ctdata0&0x00008000)>>15;l62 = np.copy(ctdata0&0x00004000)>>14;l63 = np.copy(ctdata0&0x00002000)>>13;l64 = np.copy(ctdata0&0x00001000)>>12;
    l65 = np.copy(ctdata0&0x00000800)>>11;l66 = np.copy(ctdata0&0x00000400)>>10;l67 = np.copy(ctdata0&0x00000200)>>9;l68 = np.copy(ctdata0&0x00000100)>>8;
    l69 = np.copy(ctdata0&0x00000080)>>7;l70 = np.copy(ctdata0&0x00000040)>>6;l71 = np.copy(ctdata0&0x00000020)>>5;l72 = np.copy(ctdata0&0x00000010)>>4;
    l73 = np.copy(ctdata0&0x00000008)>>3;l74 = np.copy(ctdata0&0x00000004)>>2;l75 = np.copy(ctdata0&0x00000002)>>1;l76 = np.copy(ctdata0&0x00000001);
    
    # Ciphertext ctdata1 register
    s_58 = np.copy(ctdata1&0x80000000)>>31;s_59 = np.copy(ctdata1&0x40000000)>>30;s_60 = np.copy(ctdata1&0x20000000)>>29;s_61 = np.copy(ctdata1&0x10000000)>>28;
    s_62 = np.copy(ctdata1&0x08000000)>>27;s_63 = np.copy(ctdata1&0x04000000)>>26;s_64 = np.copy(ctdata1&0x02000000)>>25;s_65 = np.copy(ctdata1&0x01000000)>>24;
    s_66 = np.copy(ctdata1&0x00800000)>>23;s_67 = np.copy(ctdata1&0x00400000)>>22;s_68 = np.copy(ctdata1&0x00200000)>>21;s_69 = np.copy(ctdata1&0x00100000)>>20;
    s_70 = np.copy(ctdata1&0x00080000)>>19;l_58 = np.copy(ctdata1&0x00040000)>>18;l_59 = np.copy(ctdata1&0x00020000)>>17;l_60 = np.copy(ctdata1&0x00010000)>>16;
    l_61 = np.copy(ctdata1&0x00008000)>>15;l_62 = np.copy(ctdata1&0x00004000)>>14;l_63 = np.copy(ctdata1&0x00002000)>>13;l_64 = np.copy(ctdata1&0x00001000)>>12;
    l_65 = np.copy(ctdata1&0x00000800)>>11;l_66 = np.copy(ctdata1&0x00000400)>>10;l_67 = np.copy(ctdata1&0x00000200)>>9;l_68 = np.copy(ctdata1&0x00000100)>>8;
    l_69 = np.copy(ctdata1&0x00000080)>>7;l_70 = np.copy(ctdata1&0x00000040)>>6;l_71 = np.copy(ctdata1&0x00000020)>>5;l_72 = np.copy(ctdata1&0x00000010)>>4;
    l_73 = np.copy(ctdata1&0x00000008)>>3;l_74 = np.copy(ctdata1&0x00000004)>>2;l_75 = np.copy(ctdata1&0x00000002)>>1;l_76 = np.copy(ctdata1&0x00000001);
     
    # Ciphertext assigns the difference
    s57 = np.copy(l76^s62^s61*s64^s66*IR[96]^k114); s_57 = np.copy(l_76^s_62^s_61*s_64^s_66*IR[96]^k114);
    s56 = np.copy(l75^s61^s60*s63^s65*IR[95]^k112); s_56 = np.copy(l_75^s_61^s_60*s_63^s_65*IR[95]^k112);
    s55 = np.copy(l74^s60^s59*s62^s64*IR[94]^k110); s_55 = np.copy(l_74^s_60^s_59*s_62^s_64*IR[94]^k110);
    s54 = np.copy(l73^s59^s58*s61^s63*IR[93]^k108); s_54 = np.copy(l_73^s_59^s_58*s_61^s_63*IR[93]^k108);
    s53 = np.copy(l72^s58^s57*s60^s62*IR[92]^k106); s_53 = np.copy(l_72^s_58^s_57*s_60^s_62*IR[92]^k106);
    s52 = np.copy(l71^s57^s56*s59^s61*IR[91]^k104); s_52 = np.copy(l_71^s_57^s_56*s_59^s_61*IR[91]^k104);
    s51 = np.copy(l70^s56^s55*s58^s60*IR[90]^k102); s_51 = np.copy(l_70^s_56^s_55*s_58^s_60*IR[90]^k102);
    s50 = np.copy(l69^s55^s54*s57^s59*IR[89]^k100); s_50 = np.copy(l_69^s_55^s_54*s_57^s_59*IR[89]^k100);
    s49 = np.copy(l68^s54^s53*s56^s58*IR[88]^k98);  s_49 = np.copy(l_68^s_54^s_53*s_56^s_58*IR[88]^k98); 
    
    l57 = np.copy(s70^l68^l63*l65^l67*l72^k115); l_57 = np.copy(s_70^l_68^l_63*l_65^l_67*l_72^k115);
    l56 = np.copy(s69^l67^l62*l64^l66*l71^k113); l_56 = np.copy(s_69^l_67^l_62*l_64^l_66*l_71^k113);
    l55 = np.copy(s68^l66^l61*l63^l65*l70^k111); l_55 = np.copy(s_68^l_66^l_61*l_63^l_65*l_70^k111);
    l54 = np.copy(s67^l65^l60*l62^l64*l69^k109); l_54 = np.copy(s_67^l_65^l_60*l_62^l_64*l_69^k109);
    l53 = np.copy(s66^l64^l59*l61^l63*l68^k107); l_53 = np.copy(s_66^l_64^l_59*l_61^l_63*l_68^k107);
    l52 = np.copy(s65^l63^l58*l60^l62*l67^k105); l_52 = np.copy(s_65^l_63^l_58*l_60^l_62*l_67^k105);
    l51 = np.copy(s64^l62^l57*l59^l61*l66^k103); l_51 = np.copy(s_64^l_62^l_57*l_59^l_61*l_66^k103);
    
    
    c0 = np.copy(l63^l_63);c1 = np.copy(l62^l_62);c2 = np.copy(l61^l_61);c3 = np.copy(l60^l_60);
    c4 = np.copy(l59^l_59);c5 = np.copy(l58^l_58);c6 = np.copy(l57^l_57);c7 = np.copy(l56^l_56);
    c8 = np.copy(l55^l_55);c9 = np.copy(l54^l_54);c10 = np.copy(l53^l_53);c11 = np.copy(l52^l_52);c12 = np.copy(l51^l_51);
    c13 = np.copy((s63^l61^l56*l58^l60*l65)^(s_63^l_61^l_56*l_58^l_60*l_65));
    c14 = np.copy((s62^l60^l55*l57^l59*l64)^(s_62^l_60^l_55*l_57^l_59*l_64));
    c15 = np.copy((s61^l59^l54*l56^l58*l63)^(s_61^l_59^l_54*l_56^l_58*l_63));
    c16 = np.copy((s60^l58^l53*l55^l57*l62)^(s_60^l_58^l_53*l_55^l_57*l_62));
    c17 = np.copy((s59^l57^l52*l54^l56*l61)^(s_59^l_57^l_52*l_54^l_56*l_61));
    c18 = np.copy((s58^l56^l51*l53^l55*l60)^(s_58^l_56^l_51*l_53^l_55*l_60));
    c19 = np.copy(s57^s_57);c20 = np.copy(s56^s_56);c21 = np.copy(s55^s_55);c22 = np.copy(s54^s_54);
    c23 = np.copy(s53^s_53);c24 = np.copy(s52^s_52);c25 = np.copy(s51^s_51);c26 = np.copy(s50^s_50);c27 = np.copy(s49^s_49);
    c28 = np.copy((l67^s53^s52*s55^s57*IR[87])^(l_67^s_53^s_52*s_55^s_57*IR[87]));
    c29 = np.copy((l66^s52^s51*s54^s56*IR[86])^(l_66^s_52^s_51*s_54^s_56*IR[86]));
    c30 = np.copy((l65^s51^s50*s53^s55*IR[85])^(l_65^s_51^s_50*s_53^s_55*IR[85]));
    c31 = np.copy((l64^s50^s49*s52^s54*IR[84])^(l_64^s_50^s_49*s_52^s_54*IR[84]));
    
    c31=c31<<31;c30=c30<<30;c29=c29<<29;c28=c28<<28;c27=c27<<27;c26=c26<<26;c25=c25<<25;c24=c24<<24;
    c23=c23<<23;c22=c22<<22;c21=c21<<21;c20=c20<<20;c19=c19<<19;c18=c18<<18;c17=c17<<17;c16=c16<<16;
    c15=c15<<15;c14=c14<<14;c13=c13<<13;c12=c12<<12;c11=c11<<11;c10=c10<<10;c9=c9<<9;c8=c8<<8;
    c7=c7<<7;c6=c6<<6;c5=c5<<5;c4=c4<<4;c3=c3<<3;c2=c2<<2;c1=c1<<1;c0=c0;
    ctdata=0x0^(c31^c30^c29^c28^c27^c26^c25^c24^c23^c22^c21^c20^c19^c18^c17^c16^c15^c14^c13^c12^c11^c10^c9^c8^c7^c6^c5^c4^c3^c2^c1^c0); 
    return ctdata

# 7 rounds of decryption using the guessed key
def dec_rounds1(ctdata0,ctdata1,ck1):
    k = np.copy(ck1);
    k102=np.copy(k&0x2000)>>13;
    k103=np.copy(k&0x1000)>>12;
    k104=np.copy(k&0x800)>>11;
    k105=np.copy(k&0x400)>>10;
    k106=np.copy(k&0x200)>>9;
    k107=np.copy(k&0x100)>>8;
    k108=np.copy(k&0x80)>>7;
    k109=np.copy(k&0x40)>>6;
    k110=np.copy(k&0x20)>>5;
    k111=np.copy(k&0x10)>>4;
    k112=np.copy(k&0x8)>>3;
    k113=np.copy(k&0x4)>>2;
    k114=np.copy(k&0x2)>>1;
    k115=np.copy(k&0x1);

    s58 = np.copy(ctdata0&0x80000000)>>31;s59 = np.copy(ctdata0&0x40000000)>>30;s60 = np.copy(ctdata0&0x20000000)>>29;s61 = np.copy(ctdata0&0x10000000)>>28;
    s62 = np.copy(ctdata0&0x08000000)>>27;s63 = np.copy(ctdata0&0x04000000)>>26;s64 = np.copy(ctdata0&0x02000000)>>25;s65 = np.copy(ctdata0&0x01000000)>>24;
    s66 = np.copy(ctdata0&0x00800000)>>23;s67 = np.copy(ctdata0&0x00400000)>>22;s68 = np.copy(ctdata0&0x00200000)>>21;s69 = np.copy(ctdata0&0x00100000)>>20;
    s70 = np.copy(ctdata0&0x00080000)>>19;l58 = np.copy(ctdata0&0x00040000)>>18;l59 = np.copy(ctdata0&0x00020000)>>17;l60 = np.copy(ctdata0&0x00010000)>>16;
    l61 = np.copy(ctdata0&0x00008000)>>15;l62 = np.copy(ctdata0&0x00004000)>>14;l63 = np.copy(ctdata0&0x00002000)>>13;l64 = np.copy(ctdata0&0x00001000)>>12;
    l65 = np.copy(ctdata0&0x00000800)>>11;l66 = np.copy(ctdata0&0x00000400)>>10;l67 = np.copy(ctdata0&0x00000200)>>9;l68 = np.copy(ctdata0&0x00000100)>>8;
    l69 = np.copy(ctdata0&0x00000080)>>7;l70 = np.copy(ctdata0&0x00000040)>>6;l71 = np.copy(ctdata0&0x00000020)>>5;l72 = np.copy(ctdata0&0x00000010)>>4;
    l73 = np.copy(ctdata0&0x00000008)>>3;l74 = np.copy(ctdata0&0x00000004)>>2;l75 = np.copy(ctdata0&0x00000002)>>1;l76 = np.copy(ctdata0&0x00000001);
    

    s_58 = np.copy(ctdata1&0x80000000)>>31;s_59 = np.copy(ctdata1&0x40000000)>>30;s_60 = np.copy(ctdata1&0x20000000)>>29;s_61 = np.copy(ctdata1&0x10000000)>>28;
    s_62 = np.copy(ctdata1&0x08000000)>>27;s_63 = np.copy(ctdata1&0x04000000)>>26;s_64 = np.copy(ctdata1&0x02000000)>>25;s_65 = np.copy(ctdata1&0x01000000)>>24;
    s_66 = np.copy(ctdata1&0x00800000)>>23;s_67 = np.copy(ctdata1&0x00400000)>>22;s_68 = np.copy(ctdata1&0x00200000)>>21;s_69 = np.copy(ctdata1&0x00100000)>>20;
    s_70 = np.copy(ctdata1&0x00080000)>>19;l_58 = np.copy(ctdata1&0x00040000)>>18;l_59 = np.copy(ctdata1&0x00020000)>>17;l_60 = np.copy(ctdata1&0x00010000)>>16;
    l_61 = np.copy(ctdata1&0x00008000)>>15;l_62 = np.copy(ctdata1&0x00004000)>>14;l_63 = np.copy(ctdata1&0x00002000)>>13;l_64 = np.copy(ctdata1&0x00001000)>>12;
    l_65 = np.copy(ctdata1&0x00000800)>>11;l_66 = np.copy(ctdata1&0x00000400)>>10;l_67 = np.copy(ctdata1&0x00000200)>>9;l_68 = np.copy(ctdata1&0x00000100)>>8;
    l_69 = np.copy(ctdata1&0x00000080)>>7;l_70 = np.copy(ctdata1&0x00000040)>>6;l_71 = np.copy(ctdata1&0x00000020)>>5;l_72 = np.copy(ctdata1&0x00000010)>>4;
    l_73 = np.copy(ctdata1&0x00000008)>>3;l_74 = np.copy(ctdata1&0x00000004)>>2;l_75 = np.copy(ctdata1&0x00000002)>>1;l_76 = np.copy(ctdata1&0x00000001);

    s57 = np.copy(l76^s62^s61*s64^s66*IR[96]^k114); s_57 = np.copy(l_76^s_62^s_61*s_64^s_66*IR[96]^k114);
    s56 = np.copy(l75^s61^s60*s63^s65*IR[95]^k112); s_56 = np.copy(l_75^s_61^s_60*s_63^s_65*IR[95]^k112);
    s55 = np.copy(l74^s60^s59*s62^s64*IR[94]^k110); s_55 = np.copy(l_74^s_60^s_59*s_62^s_64*IR[94]^k110);
    s54 = np.copy(l73^s59^s58*s61^s63*IR[93]^k108); s_54 = np.copy(l_73^s_59^s_58*s_61^s_63*IR[93]^k108);
    s53 = np.copy(l72^s58^s57*s60^s62*IR[92]^k106); s_53 = np.copy(l_72^s_58^s_57*s_60^s_62*IR[92]^k106);
    s52 = np.copy(l71^s57^s56*s59^s61*IR[91]^k104); s_52 = np.copy(l_71^s_57^s_56*s_59^s_61*IR[91]^k104);
    s51 = np.copy(l70^s56^s55*s58^s60*IR[90]^k102); s_51 = np.copy(l_70^s_56^s_55*s_58^s_60*IR[90]^k102);
     
    
    l57 = np.copy(s70^l68^l63*l65^l67*l72^k115); l_57 = np.copy(s_70^l_68^l_63*l_65^l_67*l_72^k115);
    l56 = np.copy(s69^l67^l62*l64^l66*l71^k113); l_56 = np.copy(s_69^l_67^l_62*l_64^l_66*l_71^k113);
    l55 = np.copy(s68^l66^l61*l63^l65*l70^k111); l_55 = np.copy(s_68^l_66^l_61*l_63^l_65*l_70^k111);
    l54 = np.copy(s67^l65^l60*l62^l64*l69^k109); l_54 = np.copy(s_67^l_65^l_60*l_62^l_64*l_69^k109);
    l53 = np.copy(s66^l64^l59*l61^l63*l68^k107); l_53 = np.copy(s_66^l_64^l_59*l_61^l_63*l_68^k107);
    l52 = np.copy(s65^l63^l58*l60^l62*l67^k105); l_52 = np.copy(s_65^l_63^l_58*l_60^l_62*l_67^k105);
    l51 = np.copy(s64^l62^l57*l59^l61*l66^k103); l_51 = np.copy(s_64^l_62^l_57*l_59^l_61*l_66^k103);
 
    s51=s51<<31;s52=s52<<30;s53=s53<<29;s54=s54<<28;s55=s55<<27;s56=s56<<26;s57=s57<<25;s58=s58<<24;
    s59=s59<<23;s60=s60<<22;s61=s61<<21;s62=s62<<20;s63=s63<<19;l51=l51<<18;l52=l52<<17;l53=l53<<16;
    l54=l54<<15;l55=l55<<14;l56=l56<<13;l57=l57<<12;l58=l58<<11;l59=l59<<10;l60=l60<<9;l61=l61<<8;
    l62=l62<<7;l63=l63<<6;l64=l64<<5;l65=l65<<4;l66=l66<<3;l67=l67<<2;l68=l68<<1;l69=l69<<0
    
    s_51=s_51<<31;s_52=s_52<<30;s_53=s_53<<29;s_54=s_54<<28;s_55=s_55<<27;s_56=s_56<<26;s_57=s_57<<25;s_58=s_58<<24;
    s_59=s_59<<23;s_60=s_60<<22;s_61=s_61<<21;s_62=s_62<<20;s_63=s_63<<19;l_51=l_51<<18;l_52=l_52<<17;l_53=l_53<<16;
    l_54=l_54<<15;l_55=l_55<<14;l_56=l_56<<13;l_57=l_57<<12;l_58=l_58<<11;l_59=l_59<<10;l_60=l_60<<9;l_61=l_61<<8;
    l_62=l_62<<7;l_63=l_63<<6;l_64=l_64<<5;l_65=l_65<<4;l_66=l_66<<3;l_67=l_67<<2;l_68=l_68<<1;l_69=l_69<<0
    
    ctdata0 = 0x0^(s51^s52^s53^s54^s55^s56^s57^s58^s59^s60^s61^s62^s63^l51^l52^l53^l54^l55^l56^l57^l58^l59^l60^l61^l62^l63^l64^l65^l66^l67^l68^l69)    
    ctdata1 = 0x0^(s_51^s_52^s_53^s_54^s_55^s_56^s_57^s_58^s_59^s_60^s_61^s_62^s_63^l_51^l_52^l_53^l_54^l_55^l_56^l_57^l_58^l_59^l_60^l_61^l_62^l_63^l_64^l_65^l_66^l_67^l_68^l_69)
    return (ctdata0,ctdata1)

# Decrypt another 13 rounds
def dec_rounds2(ctdata0,ctdata1,ck2):
    ck2=np.copy(ck2); 
    k84=np.copy(ck2&0x8000)>>15;
    k86=np.copy(ck2&0x4000)>>14;
    k88=np.copy(ck2&0x2000)>>13;
    k89=np.copy(ck2&0x1000)>>12;
    k90=np.copy(ck2&0x800)>>11;
    k91=np.copy(ck2&0x400)>>10;
    k92=np.copy(ck2&0x200)>>9;
    k93=np.copy(ck2&0x100)>>8;
    k94=np.copy(ck2&0x80)>>7;
    k95=np.copy(ck2&0x40)>>6;
    k96=np.copy(ck2&0x20)>>5;
    k97=np.copy(ck2&0x10)>>4;
    k98=np.copy(ck2&0x8)>>3;
    k99=np.copy(ck2&0x4)>>2;
    k100=np.copy(ck2&0x2)>>1;
    k101=np.copy(ck2&0x1);

    s51 = np.copy(ctdata0&0x80000000)>>31;s52 = np.copy(ctdata0&0x40000000)>>30;s53 = np.copy(ctdata0&0x20000000)>>29;s54 = np.copy(ctdata0&0x10000000)>>28;
    s55 = np.copy(ctdata0&0x08000000)>>27;s56 = np.copy(ctdata0&0x04000000)>>26;s57 = np.copy(ctdata0&0x02000000)>>25;s58 = np.copy(ctdata0&0x01000000)>>24;
    s59 = np.copy(ctdata0&0x00800000)>>23;s60 = np.copy(ctdata0&0x00400000)>>22;s61 = np.copy(ctdata0&0x00200000)>>21;s62 = np.copy(ctdata0&0x00100000)>>20;
    s63 = np.copy(ctdata0&0x00080000)>>19;l51 = np.copy(ctdata0&0x00040000)>>18;l52 = np.copy(ctdata0&0x00020000)>>17;l53 = np.copy(ctdata0&0x00010000)>>16;
    l54 = np.copy(ctdata0&0x00008000)>>15;l55 = np.copy(ctdata0&0x00004000)>>14;l56 = np.copy(ctdata0&0x00002000)>>13;l57 = np.copy(ctdata0&0x00001000)>>12;
    l58 = np.copy(ctdata0&0x00000800)>>11;l59 = np.copy(ctdata0&0x00000400)>>10;l60 = np.copy(ctdata0&0x00000200)>>9;l61 = np.copy(ctdata0&0x00000100)>>8;
    l62 = np.copy(ctdata0&0x00000080)>>7;l63 = np.copy(ctdata0&0x00000040)>>6;l64 = np.copy(ctdata0&0x00000020)>>5;l65 = np.copy(ctdata0&0x00000010)>>4;
    l66 = np.copy(ctdata0&0x00000008)>>3;l67 = np.copy(ctdata0&0x00000004)>>2;l68 = np.copy(ctdata0&0x00000002)>>1;l69 = np.copy(ctdata0&0x00000001);
    
  
    s_51 = np.copy(ctdata1&0x80000000)>>31;s_52 = np.copy(ctdata1&0x40000000)>>30;s_53 = np.copy(ctdata1&0x20000000)>>29;s_54 = np.copy(ctdata1&0x10000000)>>28;
    s_55 = np.copy(ctdata1&0x08000000)>>27;s_56 = np.copy(ctdata1&0x04000000)>>26;s_57 = np.copy(ctdata1&0x02000000)>>25;s_58 = np.copy(ctdata1&0x01000000)>>24;
    s_59 = np.copy(ctdata1&0x00800000)>>23;s_60 = np.copy(ctdata1&0x00400000)>>22;s_61 = np.copy(ctdata1&0x00200000)>>21;s_62 = np.copy(ctdata1&0x00100000)>>20;
    s_63 = np.copy(ctdata1&0x00080000)>>19;l_51 = np.copy(ctdata1&0x00040000)>>18;l_52 = np.copy(ctdata1&0x00020000)>>17;l_53 = np.copy(ctdata1&0x00010000)>>16;
    l_54 = np.copy(ctdata1&0x00008000)>>15;l_55 = np.copy(ctdata1&0x00004000)>>14;l_56 = np.copy(ctdata1&0x00002000)>>13;l_57 = np.copy(ctdata1&0x00001000)>>12;
    l_58 = np.copy(ctdata1&0x00000800)>>11;l_59 = np.copy(ctdata1&0x00000400)>>10;l_60 = np.copy(ctdata1&0x00000200)>>9;l_61 = np.copy(ctdata1&0x00000100)>>8;
    l_62 = np.copy(ctdata1&0x00000080)>>7;l_63 = np.copy(ctdata1&0x00000040)>>6;l_64 = np.copy(ctdata1&0x00000020)>>5;l_65 = np.copy(ctdata1&0x00000010)>>4;
    l_66 = np.copy(ctdata1&0x00000008)>>3;l_67 = np.copy(ctdata1&0x00000004)>>2;l_68 = np.copy(ctdata1&0x00000002)>>1;l_69 = np.copy(ctdata1&0x00000001);
     
   
    s50 = np.copy(l69^s55^s54*s57^s59*IR[89]^k100); s_50 = np.copy(l_69^s_55^s_54*s_57^s_59*IR[89]^k100);
    s49 = np.copy(l68^s54^s53*s56^s58*IR[88]^k98);  s_49 = np.copy(l_68^s_54^s_53*s_56^s_58*IR[88]^k98); 
    s48 = np.copy(l67^s53^s52*s55^s57*IR[87]^k96);  s_48 = np.copy(l_67^s_53^s_52*s_55^s_57*IR[87]^k96); 
    s47 = np.copy(l66^s52^s51*s54^s56*IR[86]^k94);  s_47 = np.copy(l_66^s_52^s_51*s_54^s_56*IR[86]^k94); 
    s46 = np.copy(l65^s51^s50*s53^s55*IR[85]^k92);  s_46 = np.copy(l_65^s_51^s_50*s_53^s_55*IR[85]^k92); 
    s45 = np.copy(l64^s50^s49*s52^s54*IR[84]^k90);  s_45 = np.copy(l_64^s_50^s_49*s_52^s_54*IR[84]^k90); 
    s44 = np.copy(l63^s49^s48*s51^s53*IR[83]^k88);  s_44 = np.copy(l_63^s_49^s_48*s_51^s_53*IR[83]^k88); 
    s43 = np.copy(l62^s48^s47*s50^s52*IR[82]^k86);  s_43 = np.copy(l_62^s_48^s_47*s_50^s_52*IR[82]^k86);
    s42 = np.copy(l61^s47^s46*s49^s51*IR[81]^k84);  s_42 = np.copy(l_61^s_47^s_46*s_49^s_51*IR[81]^k84);
    
    l50 = np.copy(s63^l61^l56*l58^l60*l65^k101); l_50 = np.copy(s_63^l_61^l_56*l_58^l_60*l_65^k101);
    l49 = np.copy(s62^l60^l55*l57^l59*l64^k99); l_49 = np.copy(s_62^l_60^l_55*l_57^l_59*l_64^k99);
    l48 = np.copy(s61^l59^l54*l56^l58*l63^k97); l_48 = np.copy(s_61^l_59^l_54*l_56^l_58*l_63^k97);
    l47 = np.copy(s60^l58^l53*l55^l57*l62^k95); l_47 = np.copy(s_60^l_58^l_53*l_55^l_57*l_62^k95);
    l46 = np.copy(s59^l57^l52*l54^l56*l61^k93); l_46 = np.copy(s_59^l_57^l_52*l_54^l_56*l_61^k93);
    l45 = np.copy(s58^l56^l51*l53^l55*l60^k91); l_45 = np.copy(s_58^l_56^l_51*l_53^l_55*l_60^k91);
    l44 = np.copy(s57^l55^l50*l52^l54*l59^k89); l_44 = np.copy(s_57^l_55^l_50*l_52^l_54*l_59^k89);
    

    c0 = np.copy(l56^l_56);c1 = np.copy(l55^l_55);c2 = np.copy(l54^l_54);c3 = np.copy(l53^l_53);
    c4 = np.copy(l52^l_52);c5 = np.copy(l51^l_51);c6 = np.copy(l50^l_50);c7 = np.copy(l49^l_49);
    c8 = np.copy(l48^l_48);c9 = np.copy(l47^l_47);c10 = np.copy(l46^l_46);c11 = np.copy(l45^l_45);c12 = np.copy(l44^l_44);
    c13 = np.copy((s56^l54^l49*l51^l53*l58)^(s_56^l_54^l_49*l_51^l_53*l_58));
    c14 = np.copy((s55^l53^l48*l50^l52*l57)^(s_55^l_53^l_48*l_50^l_52*l_57));
    c15 = np.copy((s54^l52^l47*l49^l51*l56)^(s_54^l_52^l_47*l_49^l_51*l_56));
    c16 = np.copy((s53^l51^l46*l48^l50*l55)^(s_53^l_51^l_46*l_48^l_50*l_55));
    c17 = np.copy((s52^l50^l45*l47^l49*l54)^(s_52^l_50^l_45*l_47^l_49*l_54));
    c18 = np.copy((s51^l49^l44*l46^l48*l53)^(s_51^l_49^l_44*l_46^l_48*l_53));
    c19 = np.copy(s50^s_50);c20 = np.copy(s49^s_49);c21 = np.copy(s48^s_48);c22 = np.copy(s47^s_47);
    c23 = np.copy(s46^s_46);c24 = np.copy(s45^s_45);c25 = np.copy(s44^s_44);c26 = np.copy(s43^s_43);c27 = np.copy(s42^s_42);
    c28 = np.copy((l60^s46^s45*s48^s50*IR[80])^(l_60^s_46^s_45*s_48^s_50*IR[80]));
    c29 = np.copy((l59^s45^s44*s47^s49*IR[79])^(l_59^s_45^s_44*s_47^s_49*IR[79]));
    c30 = np.copy((l58^s44^s43*s46^s48*IR[78])^(l_58^s_44^s_43*s_46^s_48*IR[78]));
    c31 = np.copy((l57^s43^s42*s45^s47*IR[77])^(l_57^s_43^s_42*s_45^s_47*IR[77]));
    
    c31=c31<<31;c30=c30<<30;c29=c29<<29;c28=c28<<28;c27=c27<<27;c26=c26<<26;c25=c25<<25;c24=c24<<24;
    c23=c23<<23;c22=c22<<22;c21=c21<<21;c20=c20<<20;c19=c19<<19;c18=c18<<18;c17=c17<<17;c16=c16<<16;
    c15=c15<<15;c14=c14<<14;c13=c13<<13;c12=c12<<12;c11=c11<<11;c10=c10<<10;c9=c9<<9;c8=c8<<8;
    c7=c7<<7;c6=c6<<6;c5=c5<<5;c4=c4<<4;c3=c3<<3;c2=c2<<2;c1=c1<<1;c0=c0;
    ctdata=0x0^(c31^c30^c29^c28^c27^c26^c25^c24^c23^c22^c21^c20^c19^c18^c17^c16^c15^c14^c13^c12^c11^c10^c9^c8^c7^c6^c5^c4^c3^c2^c1^c0); 
    return ctdata


