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

#Data needed to generate wrong key profile
def make_recover_data1(n, nr, diff, keys, k):
  num =48
  X = []
  #k = np.repeat(k, n)
  k = np.copy(k);
  k148=np.copy(k&0x8000)>>15;  
  k150=np.copy(k&0x4000)>>14;
  k152=np.copy(k&0x2000)>>13;
  k153=np.copy(k&0x1000)>>12;
  k154=np.copy(k&0x800)>>11;
  k155=np.copy(k&0x400)>>10;
  k156=np.copy(k&0x200)>>9;
  k157=np.copy(k&0x100)>>8;
  k158=np.copy(k&0x80)>>7;
  k159=np.copy(k&0x40)>>6;
  k160=np.copy(k&0x20)>>5;
  k161=np.copy(k&0x10)>>4;
  k162=np.copy(k&0x8)>>3;
  k163=np.copy(k&0x4)>>2;
  k164=np.copy(k&0x2)>>1;
  k165=np.copy(k&0x1);
  for i in range(int(num)):
     plain0 = np.frombuffer(urandom(8*n),dtype=np.uint64)%pow(2,48);
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
     #Generate key registers in conditions
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
     p26 = np.copy(p17^p19*p11^p13*p4^k3^1);#s21=1
     s21 = np.copy(p26^p17^p19*p11^p13*p4^k3);
     s22 = np.copy(p25^p16^p18*p10^p12*p3^k3);
     p16 = np.copy(p37^p31^p34*s21^(p25^p18*p10^p12*p3^k3)^k10);#c(9,0)
     p41 = np.copy(p35^p38*p30^p29*IR[3]^k6);#c(10,2)
      
     l29 = np.copy(p47^p41^p44*p36^p35*IR[0]^k0);
     l30 = np.copy(p46^p40^p43*p35^p34*IR[0]^k0);
     s26 = np.copy(p21^p12^p14*p6^p8*l29^k7)
     s27 = np.copy(p20^p11^p13*p5^p7*l30^k9)
     p21 = np.copy(p32^(p17^p26^p19*p11^p13*p4^k3)^(p12^p14*p6^p8*l29^k7)^s27*IR[7]^k14);#c(15,0)
     p19 = np.copy(p28^p21*p13^p15*p6^k1)#s19=0
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
     p39 = np.copy(p13^(p33^s20*IR[4]^k8)^k15)#s34=0
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
     p23 = np.copy(p35^p29^p32*s23^(p14^p16*p8^p10*p1^k5)^k12^1);#l41=1
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
     myKATAN = KATAN(keys, 48, nr)
     ctdata0 = myKATAN.enc(plain0)
     ctdata1 = myKATAN.enc(plain1) 
     ctdata = ctdata0^ctdata1
     
     #Ciphertext ctdata0 register
     s166 = np.copy(ctdata0&0x800000000000)>>47;s167 = np.copy(ctdata0&0x400000000000)>>46;s168 = np.copy(ctdata0&0x200000000000)>>45;s169 = np.copy(ctdata0&0x100000000000)>>44;
     s170 = np.copy(ctdata0&0x080000000000)>>43;s171 = np.copy(ctdata0&0x040000000000)>>42;s172 = np.copy(ctdata0&0x020000000000)>>41;s173 = np.copy(ctdata0&0x010000000000)>>40;
     s174 = np.copy(ctdata0&0x008000000000)>>39;s175 = np.copy(ctdata0&0x004000000000)>>38;s176 = np.copy(ctdata0&0x002000000000)>>37;s177 = np.copy(ctdata0&0x001000000000)>>36;
     s178 = np.copy(ctdata0&0x000800000000)>>35;s179 = np.copy(ctdata0&0x000400000000)>>34;s180 = np.copy(ctdata0&0x000200000000)>>33;s181 = np.copy(ctdata0&0x000100000000)>>32;
     s182 = np.copy(ctdata0&0x000080000000)>>31;s183 = np.copy(ctdata0&0x000040000000)>>30;s184 = np.copy(ctdata0&0x000020000000)>>29;l166 = np.copy(ctdata0&0x000010000000)>>28;
     l167 = np.copy(ctdata0&0x000008000000)>>27;l168 = np.copy(ctdata0&0x000004000000)>>26;l169 = np.copy(ctdata0&0x000002000000)>>25;l170 = np.copy(ctdata0&0x000001000000)>>24;
     l171 = np.copy(ctdata0&0x000000800000)>>23;l172 = np.copy(ctdata0&0x000000400000)>>22;l173 = np.copy(ctdata0&0x000000200000)>>21;l174 = np.copy(ctdata0&0x000000100000)>>20;
     l175 = np.copy(ctdata0&0x000000080000)>>19;l176 = np.copy(ctdata0&0x000000040000)>>18;l177 = np.copy(ctdata0&0x000000020000)>>17;l178 = np.copy(ctdata0&0x000000010000)>>16;
     l179 = np.copy(ctdata0&0x000000008000)>>15;l180 = np.copy(ctdata0&0x000000004000)>>14;l181 = np.copy(ctdata0&0x000000002000)>>13;l182 = np.copy(ctdata0&0x000000001000)>>12;
     l183 = np.copy(ctdata0&0x000000000800)>>11;l184 = np.copy(ctdata0&0x000000000400)>>10;l185 = np.copy(ctdata0&0x000000000200)>>9;l186 = np.copy(ctdata0&0x000000000100)>>8;
     l187 = np.copy(ctdata0&0x000000000080)>>7;l188 = np.copy(ctdata0&0x000000000040)>>6;l189 = np.copy(ctdata0&0x000000000020)>>5;l190 = np.copy(ctdata0&0x000000000010)>>4;
     l191 = np.copy(ctdata0&0x000000000008)>>3;l192 = np.copy(ctdata0&0x000000000004)>>2;l193 = np.copy(ctdata0&0x000000000002)>>1;l194 = np.copy(ctdata0&0x000000000001);
     #Ciphertext ctdata1 register
     s_166 = np.copy(ctdata1&0x800000000000)>>47;s_167 = np.copy(ctdata1&0x400000000000)>>46;s_168 = np.copy(ctdata1&0x200000000000)>>45;s_169 = np.copy(ctdata1&0x100000000000)>>44;
     s_170 = np.copy(ctdata1&0x080000000000)>>43;s_171 = np.copy(ctdata1&0x040000000000)>>42;s_172 = np.copy(ctdata1&0x020000000000)>>41;s_173 = np.copy(ctdata1&0x010000000000)>>40;
     s_174 = np.copy(ctdata1&0x008000000000)>>39;s_175 = np.copy(ctdata1&0x004000000000)>>38;s_176 = np.copy(ctdata1&0x002000000000)>>37;s_177 = np.copy(ctdata1&0x001000000000)>>36;
     s_178 = np.copy(ctdata1&0x000800000000)>>35;s_179 = np.copy(ctdata1&0x000400000000)>>34;s_180 = np.copy(ctdata1&0x000200000000)>>33;s_181 = np.copy(ctdata1&0x000100000000)>>32;
     s_182 = np.copy(ctdata1&0x000080000000)>>31;s_183 = np.copy(ctdata1&0x000040000000)>>30;s_184 = np.copy(ctdata1&0x000020000000)>>29;l_166 = np.copy(ctdata1&0x000010000000)>>28;
     l_167 = np.copy(ctdata1&0x000008000000)>>27;l_168 = np.copy(ctdata1&0x000004000000)>>26;l_169 = np.copy(ctdata1&0x000002000000)>>25;l_170 = np.copy(ctdata1&0x000001000000)>>24;
     l_171 = np.copy(ctdata1&0x000000800000)>>23;l_172 = np.copy(ctdata1&0x000000400000)>>22;l_173 = np.copy(ctdata1&0x000000200000)>>21;l_174 = np.copy(ctdata1&0x000000100000)>>20;
     l_175 = np.copy(ctdata1&0x000000080000)>>19;l_176 = np.copy(ctdata1&0x000000040000)>>18;l_177 = np.copy(ctdata1&0x000000020000)>>17;l_178 = np.copy(ctdata1&0x000000010000)>>16;
     l_179 = np.copy(ctdata1&0x000000008000)>>15;l_180 = np.copy(ctdata1&0x000000004000)>>14;l_181 = np.copy(ctdata1&0x000000002000)>>13;l_182 = np.copy(ctdata1&0x000000001000)>>12;
     l_183 = np.copy(ctdata1&0x000000000800)>>11;l_184 = np.copy(ctdata1&0x000000000400)>>10;l_185 = np.copy(ctdata1&0x000000000200)>>9;l_186 = np.copy(ctdata1&0x000000000100)>>8;
     l_187 = np.copy(ctdata1&0x000000000080)>>7;l_188 = np.copy(ctdata1&0x000000000040)>>6;l_189 = np.copy(ctdata1&0x000000000020)>>5;l_190 = np.copy(ctdata1&0x000000000010)>>4;
     l_191 = np.copy(ctdata1&0x000000000008)>>3;l_192 = np.copy(ctdata1&0x000000000004)>>2;l_193 = np.copy(ctdata1&0x000000000002)>>1;l_194 = np.copy(ctdata1&0x000000000001);

     c47 = np.copy(ctdata&0x800000000000)>>47;c46 = np.copy(ctdata&0x400000000000)>>46;c45 = np.copy(ctdata&0x200000000000)>>45;c44 = np.copy(ctdata&0x100000000000)>>44;
     c43 = np.copy(ctdata&0x080000000000)>>43;c42 = np.copy(ctdata&0x040000000000)>>42;c41 = np.copy(ctdata&0x020000000000)>>41;c40 = np.copy(ctdata&0x010000000000)>>40;
     c39 = np.copy(ctdata&0x008000000000)>>39;c38 = np.copy(ctdata&0x004000000000)>>38;c37 = np.copy(ctdata&0x002000000000)>>37;c36 = np.copy(ctdata&0x001000000000)>>36;
     c35 = np.copy(ctdata&0x000800000000)>>35;c34 = np.copy(ctdata&0x000400000000)>>34;c33 = np.copy(ctdata&0x000200000000)>>33;c32 = np.copy(ctdata&0x000100000000)>>32;
     c31 = np.copy(ctdata&0x000080000000)>>31;c30 = np.copy(ctdata&0x000040000000)>>30;c29 = np.copy(ctdata&0x000020000000)>>29;c28 = np.copy(ctdata&0x000010000000)>>28;
     c27 = np.copy(ctdata&0x000008000000)>>27;c26 = np.copy(ctdata&0x000004000000)>>26;c25 = np.copy(ctdata&0x000002000000)>>25;c24 = np.copy(ctdata&0x000001000000)>>24;
     c23 = np.copy(ctdata&0x000000800000)>>23;c22 = np.copy(ctdata&0x000000400000)>>22;c21 = np.copy(ctdata&0x000000200000)>>21;c20 = np.copy(ctdata&0x000000100000)>>20;
     c19 = np.copy(ctdata&0x000000080000)>>19;c18 = np.copy(ctdata&0x000000040000)>>18;c17 = np.copy(ctdata&0x000000020000)>>17;c16 = np.copy(ctdata&0x000000010000)>>16;
     c15 = np.copy(ctdata&0x000000008000)>>15;c14 = np.copy(ctdata&0x000000004000)>>14;c13 = np.copy(ctdata&0x000000002000)>>13;c12 = np.copy(ctdata&0x000000001000)>>12;
     c11 = np.copy(ctdata&0x000000000800)>>11;c10 = np.copy(ctdata&0x000000000400)>>10;c9 = np.copy(ctdata&0x000000000200)>>9;c8 = np.copy(ctdata&0x000000000100)>>8;
     c7 = np.copy(ctdata&0x000000000080)>>7;c6 = np.copy(ctdata&0x000000000040)>>6;c5 = np.copy(ctdata&0x000000000020)>>5;c4 = np.copy(ctdata&0x000000000010)>>4;
     c3 = np.copy(ctdata&0x000000000008)>>3;c2 = np.copy(ctdata&0x000000000004)>>2;c1 = np.copy(ctdata&0x000000000002)>>1;c0 = np.copy(ctdata&0x000000000001);

     s165=np.copy(l194^s171^s168*s176^s177*IR[81]^k164);s_165=np.copy(l_194^s_171^s_168*s_176^s_177*IR[81]^k164);
     s164=np.copy(l193^s170^s167*s175^s176*IR[81]^k164);s_164=np.copy(l_193^s_170^s_167*s_175^s_176*IR[81]^k164);
     s163=np.copy(l192^s169^s166*s174^s175*IR[80]^k162);s_163=np.copy(l_192^s_169^s_166*s_174^s_175*IR[80]^k162);
     s162=np.copy(l191^s168^s165*s173^s174*IR[80]^k162);s_162=np.copy(l_191^s_168^s_165*s_173^s_174*IR[80]^k162);
     s161=np.copy(l190^s167^s164*s172^s173*IR[79]^k160);s_161=np.copy(l_190^s_167^s_164*s_172^s_173*IR[79]^k160);
     s160=np.copy(l189^s166^s163*s171^s172*IR[79]^k160);s_160=np.copy(l_189^s_166^s_163*s_171^s_172*IR[79]^k160);
     s159=np.copy(l188^s165^s162*s170^s171*IR[78]^k158);s_159=np.copy(l_188^s_165^s_162*s_170^s_171*IR[78]^k158);
     s158=np.copy(l187^s164^s161*s169^s170*IR[78]^k158);s_158=np.copy(l_187^s_164^s_161*s_169^s_170*IR[78]^k158);
     s157=np.copy(l186^s163^s160*s168^s169*IR[77]^k156);s_157=np.copy(l_186^s_163^s_160*s_168^s_169*IR[77]^k156);
     s156=np.copy(l185^s162^s159*s167^s168*IR[77]^k156);s_156=np.copy(l_185^s_162^s_159*s_167^s_168*IR[77]^k156);
     s155=np.copy(l184^s161^s158*s166^s167*IR[76]^k154);s_155=np.copy(l_184^s_161^s_158*s_166^s_167*IR[76]^k154);
     s154=np.copy(l183^s160^s157*s165^s166*IR[76]^k154);s_154=np.copy(l_183^s_160^s_157*s_165^s_166*IR[76]^k154);
     s153=np.copy(l182^s159^s156*s164^s165*IR[75]^k152);s_153=np.copy(l_182^s_159^s_156*s_164^s_165*IR[75]^k152);
     s152=np.copy(l181^s158^s155*s163^s164*IR[75]^k152);s_152=np.copy(l_181^s_158^s_155*s_163^s_164*IR[75]^k152);
     s151=np.copy(l180^s157^s154*s162^s163*IR[74]^k150);s_151=np.copy(l_180^s_157^s_154*s_162^s_163*IR[74]^k150);
     s150=np.copy(l179^s156^s153*s161^s162*IR[74]^k150);s_150=np.copy(l_179^s_156^s_153*s_161^s_162*IR[74]^k150);
     s149=np.copy(l178^s155^s152*s160^s161*IR[73]^k148);s_149=np.copy(l_178^s_155^s_152*s_160^s_161*IR[73]^k148);
     
     l165=np.copy(s184^l174^l172*l180^l178*l187^k165);l_165=np.copy(s_184^l_174^l_172*l_180^l_178*l_187^k165);
     l164=np.copy(s183^l173^l171*l179^l177*l186^k165);l_164=np.copy(s_183^l_173^l_171*l_179^l_177*l_186^k165);
     l163=np.copy(s182^l172^l170*l178^l176*l185^k163);l_163=np.copy(s_182^l_172^l_170*l_178^l_176*l_185^k163);
     l162=np.copy(s181^l171^l169*l177^l175*l184^k163);l_162=np.copy(s_181^l_171^l_169*l_177^l_175*l_184^k163);
     l161=np.copy(s180^l170^l168*l176^l174*l183^k161);l_161=np.copy(s_180^l_170^l_168*l_176^l_174*l_183^k161);
     l160=np.copy(s179^l169^l167*l175^l173*l182^k161);l_160=np.copy(s_179^l_169^l_167*l_175^l_173*l_182^k161);
     l159=np.copy(s178^l168^l166*l174^l172*l181^k159);l_159=np.copy(s_178^l_168^l_166*l_174^l_172*l_181^k159);
     l158=np.copy(s177^l167^l165*l173^l171*l180^k159);l_158=np.copy(s_177^l_167^l_165*l_173^l_171*l_180^k159);
     l157=np.copy(s176^l166^l164*l172^l170*l179^k157);l_157=np.copy(s_176^l_166^l_164*l_172^l_170*l_179^k157);
     l156=np.copy(s175^l165^l163*l171^l169*l178^k157);l_156=np.copy(s_175^l_165^l_163*l_171^l_169*l_178^k157);
     l155=np.copy(s174^l164^l162*l170^l168*l177^k155);l_155=np.copy(s_174^l_164^l_162*l_170^l_168*l_177^k155);
     l154=np.copy(s173^l163^l161*l169^l167*l176^k155);l_154=np.copy(s_173^l_163^l_161*l_169^l_167*l_176^k155);
     l153=np.copy(s172^l162^l160*l168^l166*l175^k153);l_153=np.copy(s_172^l_162^l_160*l_168^l_166*l_175^k153);


     c29 = np.copy(s164^s_164);
     c30 = np.copy(s163^s_163);
     c31 = np.copy(s162^s_162);
     c32 = np.copy(s161^s_161);
     c33 = np.copy(s160^s_160);
     c34 = np.copy(s159^s_159);
     c35 = np.copy(s158^s_158);
     c36 = np.copy(s157^s_157);
     c37 = np.copy(s156^s_156);
     c38 = np.copy(s155^s_155);
     c39 = np.copy(s154^s_154);
     c40 = np.copy(s153^s_153);
     c41 = np.copy(s152^s_152);
     c42 = np.copy(s151^s_151);
     c43 = np.copy((l179^s156^s153*s161^s162*IR[74])^(l_179^s_156^s_153*s_161^s_162*IR[74]));
     c44 = np.copy((l178^s155^s152*s160^s161*IR[73])^(l_178^s_155^s_152*s_160^s_161*IR[43]));
     c45 = np.copy((l177^s154^s151*s159^s160*IR[73])^(l_177^s_154^s_151*s_159^s_160*IR[73]));
     c46 = np.copy((l176^s153^s150*s158^s159*IR[72])^(l_176^s_153^s_150*s_158^s_159*IR[72]));
     c47 = np.copy((l175^s152^s149*s157^s158*IR[72])^(l_175^s_152^s_149*s_157^s_158*IR[72]));

     c0 = np.copy(l174^l_174);c1 = np.copy(l173^l_173);c2 = np.copy(l172^l_172);c3 = np.copy(l171^l_171);
     c4 = np.copy(l170^l_170);c5 = np.copy(l169^l_169);c6 = np.copy(l168^l_168);c7 = np.copy(l167^l_167);
     c8 = np.copy(l166^l_166);c9 = np.copy(l165^l_165);c10 = np.copy(l164^l_164);c11 = np.copy(l163^l_163);
     c12 = np.copy(l162^l_162);c13 = np.copy(l161^l_161);c14 = np.copy(l160^l_160);c15 = np.copy(l159^l_159);
     c16 = np.copy(l158^l_158);c17 = np.copy(l157^l_157);c18 = np.copy(l156^l_156);c19 = np.copy(l155^l_155);
     c20 = np.copy(l154^l_154);c21 = np.copy(l153^l_153);
     c22 = np.copy((s171^l161^l159*l167^l165*l174)^(s_171^l_161^l_159*l_167^l_165*l_174));
     c23 = np.copy((s170^l160^l158*l166^l164*l173)^(s_170^l_160^l_158*l_166^l_164*l_173));
     c24 = np.copy((s169^l159^l157*l165^l163*l172)^(s_169^l_159^l_157*l_165^l_163*l_172));
     c25 = np.copy((s168^l158^l156*l164^l162*l171)^(s_168^l_158^l_156*l_164^l_162*l_171));
     c26 = np.copy((s167^l157^l155*l163^l161*l170)^(s_167^l_157^l_155*l_163^l_161*l_170));
     c27 = np.copy((s166^l156^l154*l162^l160*l169)^(s_166^l_156^l_154*l_162^l_160*l_169));
     c28 = np.copy((s165^l155^l153*l161^l159*l168)^(s_165^l_155^l_153*l_161^l_159*l_168));
     

     c47=c47<<47;c46=c46<<46;c45=c45<<45;c44=c44<<44;c43=c43<<43;c42=c42<<42;c41=c41<<41;c40=c40<<40;
     c39=c39<<39;c38=c38<<38;c37=c37<<37;c36=c36<<36;c35=c35<<35;c34=c34<<34;c33=c33<<33;c32=c32<<32;
     c31=c31<<31;c30=c30<<30;c29=c29<<29;c28=c28<<28;c27=c27<<27;c26=c26<<26;c25=c25<<25;c24=c24<<24;
     c23=c23<<23;c22=c22<<22;c21=c21<<21;c20=c20<<20;c19=c19<<19;c18=c18<<18;c17=c17<<17;c16=c16<<16;
     c15=c15<<15;c14=c14<<14;c13=c13<<13;c12=c12<<12;c11=c11<<11;c10=c10<<10;c9=c9<<9;c8=c8<<8;
     c7=c7<<7;c6=c6<<6;c5=c5<<5;c4=c4<<4;c3=c3<<3;c2=c2<<2;c1=c1<<1;c0=c0;
     ctdata=0x0^(c47^c46^c45^c44^c43^c42^c41^c40^c39^c38^c37^c36^c35^c34^c33^c32^c31^c30^c29^c28^c27^c26^c25^c24^c23^c22^c21^c20^c19^c18^c17^c16^c15^c14^c13^c12^c11^c10^c9^c8^c7^c6^c5^c4^c3^c2^c1^c0); 
     
     X += [ctdata]
  #print(X)
  X = convert_to_binary(X,int(num)) 
  return(X);

#Data needed to generate wrong key profile
def make_recover_data2(n, nr, diff, keys, k):
  num =48
  X = []
  #k = np.repeat(k, n)
  ck2=np.copy(k); 
  k134=np.copy(ck2&0x8000)>>15;
  k136=np.copy(ck2&0x4000)>>14;
  k138=np.copy(ck2&0x2000)>>13;
  k139=np.copy(ck2&0x1000)>>12;
  k140=np.copy(ck2&0x800)>>11;
  k141=np.copy(ck2&0x400)>>10;
  k142=np.copy(ck2&0x200)>>9;
  k143=np.copy(ck2&0x100)>>8;
  k144=np.copy(ck2&0x80)>>7;
  k145=np.copy(ck2&0x40)>>6;
  k146=np.copy(ck2&0x20)>>5;
  k147=np.copy(ck2&0x10)>>4;
  k148=np.copy(ck2&0x8)>>3;
  k149=np.copy(ck2&0x4)>>2;
  k150=np.copy(ck2&0x2)>>1;
  k151=np.copy(ck2&0x1);
  for i in range(int(num)):
     plain0 = np.frombuffer(urandom(8*n),dtype=np.uint64)%pow(2,48);
     plain0 = np.copy(plain0)
     plain0 = np.copy(plain0&0xFFE2DFFBE508^0x000820000023)
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

     p10 = np.copy(p1^1);#c(3,0)
     p26 = np.copy(p17^p19*p11^p13*p4^k3^1);#s21=1
     s21 = np.copy(p26^p17^p19*p11^p13*p4^k3);
     s22 = np.copy(p25^p16^p18*p10^p12*p3^k3);
     p16 = np.copy(p37^p31^p34*s21^(p25^p18*p10^p12*p3^k3)^k10);#c(9,0)
     p41 = np.copy(p35^p38*p30^p29*IR[3]^k6);#c(10,2)
      
     l29 = np.copy(p47^p41^p44*p36^p35*IR[0]^k0);
     l30 = np.copy(p46^p40^p43*p35^p34*IR[0]^k0);
     s26 = np.copy(p21^p12^p14*p6^p8*l29^k7)
     s27 = np.copy(p20^p11^p13*p5^p7*l30^k9)
     p21 = np.copy(p32^(p17^p26^p19*p11^p13*p4^k3)^(p12^p14*p6^p8*l29^k7)^s27*IR[7]^k14);#c(15,0)
     p19 = np.copy(p28^p21*p13^p15*p6^k1)#s19=0
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
     p39 = np.copy(p13^(p33^s20*IR[4]^k8)^k15)#s34=0
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
     p23 = np.copy(p35^p29^p32*s23^(p14^p16*p8^p10*p1^k5)^k12^1);#l41=1
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
     myKATAN = KATAN(keys, 48, nr)
     ctdata0 = myKATAN.enc(plain0)
     ctdata1 = myKATAN.enc(plain1) 
     ctdata = ctdata0^ctdata1
     
     s152 = np.copy(ctdata0&0x800000000000)>>47;s153 = np.copy(ctdata0&0x400000000000)>>46;s154 = np.copy(ctdata0&0x200000000000)>>45;s155 = np.copy(ctdata0&0x100000000000)>>44;
     s156 = np.copy(ctdata0&0x080000000000)>>43;s157 = np.copy(ctdata0&0x040000000000)>>42;s158 = np.copy(ctdata0&0x020000000000)>>41;s159 = np.copy(ctdata0&0x010000000000)>>40;
     s160 = np.copy(ctdata0&0x008000000000)>>39;s161 = np.copy(ctdata0&0x004000000000)>>38;s162 = np.copy(ctdata0&0x002000000000)>>37;s163 = np.copy(ctdata0&0x001000000000)>>36;
     s164 = np.copy(ctdata0&0x000800000000)>>35;s165 = np.copy(ctdata0&0x000400000000)>>34;s166 = np.copy(ctdata0&0x000200000000)>>33;s167 = np.copy(ctdata0&0x000100000000)>>32;
     s168 = np.copy(ctdata0&0x000080000000)>>31;s169 = np.copy(ctdata0&0x000040000000)>>30;s170 = np.copy(ctdata0&0x000020000000)>>29;l152 = np.copy(ctdata0&0x000010000000)>>28;
     l153 = np.copy(ctdata0&0x000008000000)>>27;l154 = np.copy(ctdata0&0x000004000000)>>26;l155 = np.copy(ctdata0&0x000002000000)>>25;l156 = np.copy(ctdata0&0x000001000000)>>24;
     l157 = np.copy(ctdata0&0x000000800000)>>23;l158 = np.copy(ctdata0&0x000000400000)>>22;l159 = np.copy(ctdata0&0x000000200000)>>21;l160 = np.copy(ctdata0&0x000000100000)>>20;
     l161 = np.copy(ctdata0&0x000000080000)>>19;l162 = np.copy(ctdata0&0x000000040000)>>18;l163 = np.copy(ctdata0&0x000000020000)>>17;l164 = np.copy(ctdata0&0x000000010000)>>16;
     l165 = np.copy(ctdata0&0x000000008000)>>15;l166 = np.copy(ctdata0&0x000000004000)>>14;l167 = np.copy(ctdata0&0x000000002000)>>13;l168 = np.copy(ctdata0&0x000000001000)>>12;
     l169 = np.copy(ctdata0&0x000000000800)>>11;l170 = np.copy(ctdata0&0x000000000400)>>10;l171 = np.copy(ctdata0&0x000000000200)>>9;l172 = np.copy(ctdata0&0x000000000100)>>8;
     l173 = np.copy(ctdata0&0x000000000080)>>7;l174 = np.copy(ctdata0&0x000000000040)>>6;l175 = np.copy(ctdata0&0x000000000020)>>5;l176 = np.copy(ctdata0&0x000000000010)>>4;
     l177 = np.copy(ctdata0&0x000000000008)>>3;l178 = np.copy(ctdata0&0x000000000004)>>2;l179 = np.copy(ctdata0&0x000000000002)>>1;l180 = np.copy(ctdata0&0x000000000001);

     s_152 = np.copy(ctdata1&0x800000000000)>>47;s_153 = np.copy(ctdata1&0x400000000000)>>46;s_154 = np.copy(ctdata1&0x200000000000)>>45;s_155 = np.copy(ctdata1&0x100000000000)>>44;
     s_156 = np.copy(ctdata1&0x080000000000)>>43;s_157 = np.copy(ctdata1&0x040000000000)>>42;s_158 = np.copy(ctdata1&0x020000000000)>>41;s_159 = np.copy(ctdata1&0x010000000000)>>40;
     s_160 = np.copy(ctdata1&0x008000000000)>>39;s_161 = np.copy(ctdata1&0x004000000000)>>38;s_162 = np.copy(ctdata1&0x002000000000)>>37;s_163 = np.copy(ctdata1&0x001000000000)>>36;
     s_164 = np.copy(ctdata1&0x000800000000)>>35;s_165 = np.copy(ctdata1&0x000400000000)>>34;s_166 = np.copy(ctdata1&0x000200000000)>>33;s_167 = np.copy(ctdata1&0x000100000000)>>32;
     s_168 = np.copy(ctdata1&0x000080000000)>>31;s_169 = np.copy(ctdata1&0x000040000000)>>30;s_170 = np.copy(ctdata1&0x000020000000)>>29;l_152 = np.copy(ctdata1&0x000010000000)>>28;
     l_153 = np.copy(ctdata1&0x000008000000)>>27;l_154 = np.copy(ctdata1&0x000004000000)>>26;l_155 = np.copy(ctdata1&0x000002000000)>>25;l_156 = np.copy(ctdata1&0x000001000000)>>24;
     l_157 = np.copy(ctdata1&0x000000800000)>>23;l_158 = np.copy(ctdata1&0x000000400000)>>22;l_159 = np.copy(ctdata1&0x000000200000)>>21;l_160 = np.copy(ctdata1&0x000000100000)>>20;
     l_161 = np.copy(ctdata1&0x000000080000)>>19;l_162 = np.copy(ctdata1&0x000000040000)>>18;l_163 = np.copy(ctdata1&0x000000020000)>>17;l_164 = np.copy(ctdata1&0x000000010000)>>16;
     l_165 = np.copy(ctdata1&0x000000008000)>>15;l_166 = np.copy(ctdata1&0x000000004000)>>14;l_167 = np.copy(ctdata1&0x000000002000)>>13;l_168 = np.copy(ctdata1&0x000000001000)>>12;
     l_169 = np.copy(ctdata1&0x000000000800)>>11;l_170 = np.copy(ctdata1&0x000000000400)>>10;l_171 = np.copy(ctdata1&0x000000000200)>>9;l_172 = np.copy(ctdata1&0x000000000100)>>8;
     l_173 = np.copy(ctdata1&0x000000000080)>>7;l_174 = np.copy(ctdata1&0x000000000040)>>6;l_175 = np.copy(ctdata1&0x000000000020)>>5;l_176 = np.copy(ctdata1&0x000000000010)>>4;
     l_177 = np.copy(ctdata1&0x000000000008)>>3;l_178 = np.copy(ctdata1&0x000000000004)>>2;l_179 = np.copy(ctdata1&0x000000000002)>>1;l_180 = np.copy(ctdata1&0x000000000001);

     s151=np.copy(l180^s157^s154*s162^s163*IR[74]^k150);s_151=np.copy(l_180^s_157^s_154*s_162^s_163*IR[74]^k150);
     s150=np.copy(l179^s156^s153*s161^s162*IR[74]^k150);s_150=np.copy(l_179^s_156^s_153*s_161^s_162*IR[74]^k150);
     s149=np.copy(l178^s155^s152*s160^s161*IR[73]^k148);s_149=np.copy(l_178^s_155^s_152*s_160^s_161*IR[73]^k148);
     s148=np.copy(l177^s154^s151*s159^s160*IR[73]^k148);s_148=np.copy(l_177^s_154^s_151*s_159^s_160*IR[73]^k148);
     s147=np.copy(l176^s153^s150*s158^s159*IR[72]^k146);s_147=np.copy(l_176^s_153^s_150*s_158^s_159*IR[72]^k146);
     s146=np.copy(l175^s152^s149*s157^s158*IR[72]^k146);s_146=np.copy(l_175^s_152^s_149*s_157^s_158*IR[72]^k146);
     s145=np.copy(l174^s151^s148*s156^s157*IR[71]^k144);s_145=np.copy(l_174^s_151^s_148*s_156^s_157*IR[71]^k144);
     s144=np.copy(l173^s150^s147*s155^s156*IR[71]^k144);s_144=np.copy(l_173^s_150^s_147*s_155^s_156*IR[71]^k144);
     s143=np.copy(l172^s149^s146*s154^s155*IR[70]^k142);s_143=np.copy(l_172^s_149^s_146*s_154^s_155*IR[70]^k142);
     s142=np.copy(l171^s148^s145*s153^s154*IR[70]^k142);s_142=np.copy(l_171^s_148^s_145*s_153^s_154*IR[70]^k142);
     s141=np.copy(l170^s147^s144*s152^s153*IR[69]^k140);s_141=np.copy(l_170^s_147^s_144*s_152^s_153*IR[69]^k140);
     s140=np.copy(l169^s146^s143*s151^s152*IR[69]^k140);s_140=np.copy(l_169^s_146^s_143*s_151^s_152*IR[69]^k140);
     s139=np.copy(l168^s145^s142*s150^s151*IR[68]^k138);s_139=np.copy(l_168^s_145^s_142*s_150^s_151*IR[68]^k138);
     s138=np.copy(l167^s144^s141*s149^s150*IR[68]^k138);s_138=np.copy(l_167^s_144^s_141*s_149^s_150*IR[68]^k138);
     s137=np.copy(l166^s143^s140*s148^s149*IR[67]^k136);s_137=np.copy(l_166^s_143^s_140*s_148^s_149*IR[67]^k136);
     s136=np.copy(l165^s142^s139*s147^s148*IR[67]^k136);s_136=np.copy(l_165^s_142^s_139*s_147^s_148*IR[67]^k136);
     s135=np.copy(l164^s141^s138*s146^s147*IR[66]^k134);s_135=np.copy(l_164^s_141^s_138*s_146^s_147*IR[66]^k134);
      
     l151=np.copy(s170^l160^l158*l166^l164*l173^k151);l_151=np.copy(s_170^l_160^l_158*l_166^l_164*l_173^k151);
     l150=np.copy(s169^l159^l157*l165^l163*l172^k151);l_150=np.copy(s_169^l_159^l_157*l_165^l_163*l_172^k151);
     l149=np.copy(s168^l158^l156*l164^l162*l171^k149);l_149=np.copy(s_168^l_158^l_156*l_164^l_162*l_171^k149);
     l148=np.copy(s167^l157^l155*l163^l161*l170^k149);l_148=np.copy(s_167^l_157^l_155*l_163^l_161*l_170^k149);
     l147=np.copy(s166^l156^l154*l162^l160*l169^k147);l_147=np.copy(s_166^l_156^l_154*l_162^l_160*l_169^k147);
     l146=np.copy(s165^l155^l153*l161^l159*l168^k147);l_146=np.copy(s_165^l_155^l_153*l_161^l_159*l_168^k147);
     l145=np.copy(s164^l154^l152*l160^l158*l167^k145);l_145=np.copy(s_164^l_154^l_152*l_160^l_158*l_167^k145);
     l144=np.copy(s163^l153^l151*l159^l157*l166^k145);l_144=np.copy(s_163^l_153^l_151*l_159^l_157*l_166^k145);
     l143=np.copy(s162^l152^l150*l158^l156*l165^k143);l_143=np.copy(s_162^l_152^l_150*l_158^l_156*l_165^k143);
     l142=np.copy(s161^l151^l149*l157^l155*l164^k143);l_142=np.copy(s_161^l_151^l_149*l_157^l_155*l_164^k143);
     l141=np.copy(s160^l150^l148*l156^l154*l163^k141);l_141=np.copy(s_160^l_150^l_148*l_156^l_154*l_163^k141);
     l140=np.copy(s159^l149^l147*l155^l153*l162^k141);l_140=np.copy(s_159^l_149^l_147*l_155^l_153*l_162^k141);
     l139=np.copy(s158^l148^l146*l154^l152*l161^k139);l_139=np.copy(s_158^l_148^l_146*l_154^l_152*l_161^k139);
     l138=np.copy(s157^l147^l145*l153^l151*l160^k139);l_138=np.copy(s_157^l_147^l_145*l_153^l_151*l_160^k139);
     

     c0 = np.copy(l160^l_160);c1 = np.copy(l159^l_159);c2 = np.copy(l158^l_158);c3 = np.copy(l157^l_157);
     c4 = np.copy(l156^l_156);c5 = np.copy(l155^l_155);c6 = np.copy(l154^l_154);c7 = np.copy(l153^l_153);
     c8 = np.copy(l152^l_152);c9 = np.copy(l151^l_151);c10 = np.copy(l150^l_150);c11 = np.copy(l149^l_149);
     c12 = np.copy(l148^l_148);c13 = np.copy(l147^l_147);c14 = np.copy(l146^l_146);c15 = np.copy(l145^l_145);
     c16 = np.copy(l144^l_144);c17 = np.copy(l143^l_143);c18 = np.copy(l142^l_142);c19 = np.copy(l141^l_141);
     c20 = np.copy(l140^l_140);c21 = np.copy(l139^l_139);c22 = np.copy(l138^l_138);
     c23 = np.copy((s156^l146^l144*l152^l150*l159)^(s_156^l_146^l_144*l_152^l_150*l_159));
     c24 = np.copy((s155^l145^l143*l151^l149*l158)^(s_155^l_145^l_143*l_151^l_149*l_158));
     c25 = np.copy((s154^l144^l142*l150^l148*l157)^(s_154^l_144^l_142*l_150^l_148*l_157));
     c26 = np.copy((s153^l143^l141*l149^l147*l156)^(s_153^l_143^l_141*l_149^l_147*l_156));
     c27 = np.copy((s152^l142^l140*l148^l146*l155)^(s_152^l_142^l_140*l_148^l_146*l_155));
     c28 = np.copy((s151^l141^l139*l147^l145*l154)^(s_151^l_141^l_139*l_147^l_145*l_154));

     c29 = np.copy(s150^s_150);c30 = np.copy(s149^s_149);c31 = np.copy(s148^s_148);c32 = np.copy(s147^s_147);
     c33 = np.copy(s146^s_146);c34 = np.copy(s145^s_145);c35 = np.copy(s144^s_144);c36 = np.copy(s143^s_143);
     c37 = np.copy(s142^s_142);c38 = np.copy(s141^s_141);c39 = np.copy(s140^s_140);c40 = np.copy(s139^s_139);
     c41 = np.copy(s138^s_138);c42 = np.copy(s137^s_137);c43 = np.copy(s136^s_136);
     c44 = np.copy((s135)^(s_135));
     c45 = np.copy((l163^s140^s137*s145^s146*IR[66])^(l_163^s_140^s_137*s_145^s_146*IR[66]));
     c46 = np.copy((l162^s139^s136*s144^s145*IR[65])^(l_162^s_139^s_136*s_144^s_145*IR[65]));
     c47 = np.copy((l161^s138^s135*s143^s144*IR[65])^(l_161^s_138^s_135*s_143^s_144*IR[65]));
      

     c47=c47<<47;c46=c46<<46;c45=c45<<45;c44=c44<<44;c43=c43<<43;c42=c42<<42;c41=c41<<41;c40=c40<<40;
     c39=c39<<39;c38=c38<<38;c37=c37<<37;c36=c36<<36;c35=c35<<35;c34=c34<<34;c33=c33<<33;c32=c32<<32;
     c31=c31<<31;c30=c30<<30;c29=c29<<29;c28=c28<<28;c27=c27<<27;c26=c26<<26;c25=c25<<25;c24=c24<<24;
     c23=c23<<23;c22=c22<<22;c21=c21<<21;c20=c20<<20;c19=c19<<19;c18=c18<<18;c17=c17<<17;c16=c16<<16;
     c15=c15<<15;c14=c14<<14;c13=c13<<13;c12=c12<<12;c11=c11<<11;c10=c10<<10;c9=c9<<9;c8=c8<<8;
     c7=c7<<7;c6=c6<<6;c5=c5<<5;c4=c4<<4;c3=c3<<3;c2=c2<<2;c1=c1<<1;c0=c0;
     ctdata=0x0^(c47^c46^c45^c44^c43^c42^c41^c40^c39^c38^c37^c36^c35^c34^c33^c32^c31^c30^c29^c28^c27^c26^c25^c24^c23^c22^c21^c20^c19^c18^c17^c16^c15^c14^c13^c12^c11^c10^c9^c8^c7^c6^c5^c4^c3^c2^c1^c0);
    
     X += [ctdata]
  #print(X)
  X = convert_to_binary(X,int(num)) 
  return(X);



    
