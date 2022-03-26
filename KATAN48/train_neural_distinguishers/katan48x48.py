# -*- coding: utf-8 -*-
"""
Created on Wed Sep  8 17:16:02 2021

@author: L
"""


#!/usr/bin/env python
import numpy as np 
from os import urandom

def WORD_SIZE():
    return(48)

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
        #assert x == 0 or x == 1
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
    myKATAN = KATAN(key, 48, 254)
    ct = myKATAN.enc(plaintext)
    pt = myKATAN.dec(ct)
    print(ct)
    print(pt)
    if (ct == (0x4b7efcfb8659)):     
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
    num = 48
    X = []     
    Y = np.frombuffer(urandom(n), dtype=np.uint8)      
    Y = Y & 1
    keys = np.frombuffer(urandom(10*n),dtype=np.uint16).reshape(5,-1);
    keys = np.copy(keys);
    for i in range(int(num)):
        plain0 = np.frombuffer(urandom(8*n),dtype=np.uint64)%pow(2,48);
        plain0 = np.copy(plain0)
        plain0 = np.copy(plain0&0xFFE2DFFBE508^0x000820000023)
        # Generate 32 plaintext registers
        p47 = np.copy(plain0&0x800000000000)>>47;p46 = np.copy(plain0&0x400000000000)>>46;p45 = np.copy(plain0&0x200000000000)>>45;p44 = np.copy(plain0&0x100000000000)>>44;
        p43 = np.copy(plain0&0x080000000000)>>43;p42 = np.copy(plain0&0x040000000000)>>42;p41 = np.copy(plain0&0x020000000000)>>41;p40 = np.copy(plain0&0x010000000000)>>40;
        p39 = np.copy(plain0&0x008000000000)>>39;p38 = np.copy(plain0&0x004000000000)>>38;p37 = np.copy(plain0&0x002000000000)>>37;p36 = np.copy(plain0&0x001000000000)>>36;
        p35 = np.copy(plain0&0x000800000000)>>35;p34 = np.copy(plain0&0x000400000000)>>34;p33 = np.copy(plain0&0x000200000000)>>33;p32 = np.copy(plain0&0x000100000000)>>32;
        p31 = np.copy(plain0&0x000080000000)>>31;p30 = np.copy(plain0&0x000040000000)>>30;p29 = np.copy(plain0&0x000020000000)>>29;p28 = np.copy(plain0&0x000010000000)>>28;
        p27 = np.copy(plain0&0x000008000000)>>27;p26 = np.copy(plain0&0x000004000000)>>26;p25 = np.copy(plain0&0x000002000000)>>25;p24 = np.copy(plain0&0x000001000000)>>24;
        p23 = np.copy(plain0&0x000000800000)>>23;p22 = np.copy(plain0&0x000000400000)>>22;p21 = np.copy(plain0&0x000000200000)>>21;p20 = np.copy(plain0&0x000000100000)>>20;
        p19 = np.copy(plain0&0x000000080000)>>19;p18 = np.copy(plain0&0x000000040000)>>18;p17 = np.copy(plain0&0x000000020000)>>17;p16 = np.copy(plain0&0x000000010000)>>16;
        p15 = np.copy(plain0&0x000000008000)>>15;p14 = np.copy(plain0&0x000000004000)>>14;p13 = np.copy(plain0&0x000000002000)>>13;p12 = np.copy(plain0&0x000000001000)>>12;
        p11 = np.copy(plain0&0x000000000800)>>11;p10 = np.copy(plain0&0x000000000400)>>10;p9 = np.copy(plain0&0x000000000200)>>9;p8 = np.copy(plain0&0x000000000100)>>8;
        p7 = np.copy(plain0&0x000000000080)>>7;p6 = np.copy(plain0&0x000000000040)>>6;p5 = np.copy(plain0&0x000000000020)>>5;p4 = np.copy(plain0&0x000000000010)>>4;
        p3 = np.copy(plain0&0x000000000008)>>3;p2 = np.copy(plain0&0x000000000004)>>2;p1 = np.copy(plain0&0x000000000002)>>1;p0 = np.copy(plain0&0x000000000001);
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
        k64 = np.copy(keys[4]&0x8000)>>15;
        # Compute the plaintext and key of the condition
        p10 = np.copy(p1^1);#c(3,0)
        p26 = np.copy(p17^p19*p11^p13*p4^k3^1);#Additional conditions, s21=1
        s21 = np.copy(p26^p17^p19*p11^p13*p4^k3);
        s22 = np.copy(p25^p16^p18*p10^p12*p3^k3);
        p16 = np.copy(p37^p31^p34*s21^(p25^p18*p10^p12*p3^k3)^k10);#c(9,0)
        p41 = np.copy(p35^p38*p30^p29*IR[3]^k6);#c(10,2)
      
        l29 = np.copy(p47^p41^p44*p36^p35*IR[0]^k0);
        l30 = np.copy(p46^p40^p43*p35^p34*IR[0]^k0);
        s26 = np.copy(p21^p12^p14*p6^p8*l29^k7)
        s27 = np.copy(p20^p11^p13*p5^p7*l30^k9)
        p21 = np.copy(p32^(p17^p26^p19*p11^p13*p4^k3)^(p12^p14*p6^p8*l29^k7)^s27*IR[7]^k14);#c(15,0)
        p19 = np.copy(p28^p21*p13^p15*p6^k1)#Additional conditions, s19=0
        p40 = np.copy(p34^p37*p29^(p19^p28^p21*p13^p15*p6^k1)^k6^1^p1);#c(7,2)
      
        s19 = np.copy(p28^p19^p21*p13^p15*p6^k1)
        s20 = np.copy(p27^p18^p20*p12^p14*p5^k1);
        s21 = np.copy(p26^p17^p19*p11^p13*p4^k3);
        s22 = np.copy(p25^p16^p18*p10^p12*p3^k3)
        l30 = np.copy(p46^p40^p43*p35^p34*IR[0]^k0);
        l31 = np.copy(p45^p39^p42*p34^p33*IR[1]^k2);
        s27 = np.copy(p20^p11^p13*p5^p7*l30^k9)
        s28 = np.copy(p19^p10^p12*p4^p6*l31^k9)
        l38 = np.copy(p38^p32^p35*s20^s21*IR[4]^k8);
        l45 = np.copy(p31^s22^s19*s27^s28*IR[8]^k16);
        p27 = np.copy((p38^p32^(p18^p20*p12^p14*p5^k1)^s21*IR[4]^k8)^l45)#c(12,0)
      
        s19 = np.copy(p28^p19^p21*p13^p15*p6^k1)
        s20 = np.copy(p27^p18^p20*p12^p14*p5^k1);
        l37 = np.copy(p33^p36*s19^s20*IR[4]^k8);
        p39 = np.copy(p13^(p33^s20*IR[4]^k8)^k15)#Additional conditions, s34=0
        s19 = np.copy(p28^p19^p21*p13^p15*p6^k1)
        s20 = np.copy(p27^p18^p20*p12^p14*p5^k1);
        l29 = np.copy(p47^p41^p44*p36^p35*IR[0]^k0);
        l31 = np.copy(p45^p39^p42*p34^p33*IR[1]^k2);
        l37 = np.copy(p39^p33^p36*s19^s20*IR[4]^k8);
        p45 = np.copy(p6^(p39^p42*p34^p33*IR[1]^k2)^l29*l37^k23)#c(19,3)
      
        s19 = np.copy(p28^p19^p21*p13^p15*p6^k1)
        s20 = np.copy(p27^p18^p20*p12^p14*p5^k1);
        s21 = np.copy(p26^p17^p19*p11^p13*p4^k3);
        s23 = np.copy(p24^p15^p17*p9^p11*p2^k5)
        l29 = np.copy(p47^p41^p44*p36^p35*IR[0]^k0);
        l30 = np.copy(p46^p40^p43*p35^p34*IR[0]^k0);
        l35 = np.copy(p41^p35^p38*p30^p29*IR[3]^k6);
        s27 = np.copy(p20^p11^p13*p5^p7*l30^k9)
        s32 = np.copy(p15^p6^p8*p0^p2*l35^k13)
        l29 = np.copy(p47^p41^p44*p36^p35*IR[0]^k0);
        l36 = np.copy(p40^p34^p37*p29^s19*IR[3]^k6);
        p23 = np.copy(p35^p29^p32*s23^(p14^p16*p8^p10*p1^k5)^k12^1);#Additional conditions, l41=1
        s24 = np.copy(p23^p14^p16*p8^p10*p1^k5)
        s33 = np.copy(p14^p5^p7*l29^p1*l36^k15)
        l37 = np.copy(p39^p33^p36*s19^s20*IR[4]^k8);
        l41 = np.copy(p35^p29^p32*s23^s24*IR[6]^k12);
        l50 = np.copy(s21^s27^s24*s32^s33*IR[10]^k20); 
        p20 = np.copy(p0^l37^(s21^(p11^p13*p5^p7*l30^k9)^s24*s32^s33^k20)^k29)#c(22,3)

        s19 = np.copy(p28^p19^p21*p13^p15*p6^k1)
        s20 = np.copy(p27^p18^p20*p12^p14*p5^k1);
        s21 = np.copy(p26^p17^p19*p11^p13*p4^k3);
        s22 = np.copy(p25^p16^p18*p10^p12*p3^k3)
        s23 = np.copy(p24^p15^p17*p9^p11*p2^k5)
        s24 = np.copy(p23^p14^p16*p8^p10*p1^k5)
        s25 = np.copy(p22^p13^p15*p7^p9*p0^k7)
        l29 = np.copy(p47^p41^p44*p36^p35*IR[0]^k0);
        l30 = np.copy(p46^p40^p43*p35^p34*IR[0]^k0);
        l31 = np.copy(p45^p39^p42*p34^p33*IR[1]^k2);
        l32 = np.copy(p44^p38^p41*p33^p32*IR[1]^k2);
        l33 = np.copy(p43^p37^p40*p32^p31*IR[2]^k4);
        l34 = np.copy(p42^p36^p39*p31^p30*IR[2]^k4);
        s27 = np.copy(p20^p11^p13*p5^p7*l30^k9)
        s28 = np.copy(p19^p10^p12*p4^p6*l31^k9)
        s29 = np.copy(p18^p9^p11*p3^p5*l32^k11)
        s30 = np.copy(p17^p8^p10*p2^p4*l33^k11)
        s31 = np.copy(p16^p7^p9*p1^p3*l34^k13)
        l36 = np.copy(p40^p34^p37*p29^s19*IR[3]^k6);
        l37 = np.copy(p39^p33^p36*s19^s20*IR[4]^k8);
        l38 = np.copy(p38^p32^p35*s20^s21*IR[4]^k8);
        l39 = np.copy(p37^p31^p34*s21^s22*IR[5]^k10);
        l40 = np.copy(p36^p30^p33*s22^s23*IR[5]^k10);
        l45 = np.copy(p31^s22^s19*s27^s28*IR[8]^k16);
        l46 = np.copy(p30^s23^s20*s28^s29*IR[8]^k16);
        l47 = np.copy(p29^s24^s21*s29^k18);
        s33 = np.copy(p14^p5^p7*l29^p1*l36^k15)
        s34 = np.copy(p13^p4^p6*l30^p0*l37^k15)
        s35 = np.copy(p12^p3^p5*l31^l29*l38^k17)
        s36 = np.copy(p11^p2^p4*l32^l30*l39^k17)
        s37 = np.copy(p10^p1^p3*l33^l31*l40^k19)
        s42 = np.copy(p5^l32^l30*l38^l36*l45^k23)
        s43 = np.copy(p4^l33^l31*l39^l37*l46^k25)
        l51 = np.copy(s22^s28^s25*s33^s34*IR[11]^k22);
        l53 = np.copy(s24^s30^s27*s35^s36*IR[12]^k24);
        l60 = np.copy(s31^s37^s34*s42^s43*IR[15]^k30);
        #s57 = np.copy(l38^l47^l45*l53^l51*l60^k39)#c(23,3)
        p44 = np.copy(l38^(p29^s24^(p18^p9^p11*p3^(p38^p41*p33^p32*IR[1]^k2)^k11)^k18)^l45*l53^l51*l60^k39)#c(23,3)
      
        p10=p10<<10;p16=p16<<16;p19=p19<<19;p20=p20<<20;p21=p21<<21;p23=p23<<23;p26=p26<<26;p27=p27<<27;
        p39=p39<<39;p40=p40<<40;p41=p41<<41;p44=p44<<44;p45=p45<<45;
        plain0 = np.copy(plain0&0xCC7FF346FBFF^p10^p16^p19^p20^p21^p23^p26^p27^p39^p40^p41^p44^p45);
        plain1 = plain0 ^ diff
        num_rand_samples = np.sum(Y==0)
        plain1[Y==0] = np.frombuffer(urandom(8*num_rand_samples),dtype=np.uint64)%pow(2,48)
        myKATAN = KATAN(keys, 48, nr)
        ctdata0 = myKATAN.enc(plain0)
        ctdata1 = myKATAN.enc(plain1)
        ctdata = ctdata0^ctdata1
        #print(ctdata)
        X += [ctdata]
    X = convert_to_binary(X,int(num))
    #print(len(X))    
    return (X,Y)


    
