# -*- coding: utf-8 -*-
"""
Created on Wed Sep  8 17:16:02 2021

@author: L
"""


#!/usr/bin/env python
import numpy as np 
from os import urandom

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

# Training data for conditional neural distinguisher 
def make_train_data(n, nr, diff):     
    num =32
    X = []     
    Y = np.frombuffer(urandom(n), dtype=np.uint8)      
    Y = Y & 1
    keys = np.frombuffer(urandom(10*n),dtype=np.uint16).reshape(5,-1);
    keys = np.copy(keys);
    for i in range(int(num)):
        plain0 = np.frombuffer(urandom(4*n),dtype=np.uint32);
        plain0 = np.copy(plain0)
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
        plain1 = np.copy(plain1)
        num_rand_samples = np.sum(Y==0)
        plain1[Y==0] = np.frombuffer(urandom(4*num_rand_samples),dtype=np.uint32)
        myKATAN = KATAN(keys, 32, nr)
        ctdata0 = myKATAN.enc(plain0)
        ctdata1 = myKATAN.enc(plain1)
        ctdata = ctdata0^ctdata1
        X += [ctdata]
    X = convert_to_binary(X,num)   
    return (X,Y)



