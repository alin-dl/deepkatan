# -*- coding: utf-8 -*-
"""
Created on Wed Sep  8 17:16:02 2021

@author: L
"""


#!/usr/bin/env python
import numpy as np 
from os import urandom

def WORD_SIZE():
    return(64)

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
    bits=bits[::-1]
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
    myKATAN = KATAN(key, 64, 254)
    ct = myKATAN.enc(plaintext)
    pt = myKATAN.dec(ct)
    print(ct)
    print(pt)
    if (ct == (0x21f2e99c0fab828a)):     
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
    num = 64    
    X = []     
    Y = np.frombuffer(urandom(n), dtype=np.uint8)      
    Y = Y & 1
    keys = np.frombuffer(urandom(10*n),dtype=np.uint16).reshape(5,-1);
    keys = np.copy(keys);
    for i in range(int(num)):
        plain0 = np.frombuffer(urandom(8*n),dtype=np.uint64)
        plain0 = np.copy(plain0)
        plain1 = plain0 ^ diff
        num_rand_samples = np.sum(Y==0)
        plain1[Y==0] = np.frombuffer(urandom(8*num_rand_samples),dtype=np.uint64)
        myKATAN = KATAN(keys, 64, nr)
        ctdata0 = myKATAN.enc(plain0)
        ctdata1 = myKATAN.enc(plain1)
        ctdata = ctdata0^ctdata1
        #print(ctdata)
        X += [ctdata]
    X = convert_to_binary(X,64)
    #print(len(X[0]))    
    return (X,Y)


#Generate C_structure
def make_structure(n, nr, keys, diff=(0x2480482010080400), neutral_bits = [56, 40, 38, 26, 0]):
    num =64
    cta = [];
    ctb = [];
    for i in range(int(n)):
      plain0 = np.frombuffer(urandom(8*num),dtype=np.uint64);
      for j in neutral_bits:
        d = 1 << j;
        plain0 = np.concatenate([plain0,plain0^d]);# Generate from weak neutral bit sets
      plain0 = np.copy(plain0&0xFF6CBDFF7FBAFD5D^0x80000000000000)
      # Generate 64 plaintext registers
      p63 = np.copy(plain0&0x8000000000000000)>>63;p62 = np.copy(plain0&0x4000000000000000)>>62;p61 = np.copy(plain0&0x2000000000000000)>>61;p60 = np.copy(plain0&0x1000000000000000)>>60;
      p59 = np.copy(plain0&0x0800000000000000)>>59;p58 = np.copy(plain0&0x0400000000000000)>>58;p57 = np.copy(plain0&0x0200000000000000)>>57;p56 = np.copy(plain0&0x0100000000000000)>>56;
      p55 = np.copy(plain0&0x0080000000000000)>>55;p54 = np.copy(plain0&0x0040000000000000)>>54;p53 = np.copy(plain0&0x0020000000000000)>>53;p52 = np.copy(plain0&0x0010000000000000)>>52;
      p51 = np.copy(plain0&0x0008000000000000)>>51;p50 = np.copy(plain0&0x0004000000000000)>>50;p49 = np.copy(plain0&0x0002000000000000)>>49;p48 = np.copy(plain0&0x0001000000000000)>>48;
      p47 = np.copy(plain0&0x0000800000000000)>>47;p46 = np.copy(plain0&0x0000400000000000)>>46;p45 = np.copy(plain0&0x0000200000000000)>>45;p44 = np.copy(plain0&0x0000100000000000)>>44;
      p43 = np.copy(plain0&0x0000080000000000)>>43;p42 = np.copy(plain0&0x0000040000000000)>>42;p41 = np.copy(plain0&0x0000020000000000)>>41;p40 = np.copy(plain0&0x0000010000000000)>>40;
      p39 = np.copy(plain0&0x0000008000000000)>>39;p38 = np.copy(plain0&0x0000004000000000)>>38;p37 = np.copy(plain0&0x0000002000000000)>>37;p36 = np.copy(plain0&0x0000001000000000)>>36;
      p35 = np.copy(plain0&0x0000000800000000)>>35;p34 = np.copy(plain0&0x0000000400000000)>>34;p33 = np.copy(plain0&0x0000000200000000)>>33;p32 = np.copy(plain0&0x0000000100000000)>>32;
      p31 = np.copy(plain0&0x0000000080000000)>>31;p30 = np.copy(plain0&0x0000000040000000)>>30;p29 = np.copy(plain0&0x0000000020000000)>>29;p28 = np.copy(plain0&0x0000000010000000)>>28;
      p27 = np.copy(plain0&0x0000000008000000)>>27;p26 = np.copy(plain0&0x0000000004000000)>>26;p25 = np.copy(plain0&0x0000000002000000)>>25;p24 = np.copy(plain0&0x0000000001000000)>>24;
      p23 = np.copy(plain0&0x0000000000800000)>>23;p22 = np.copy(plain0&0x0000000000400000)>>22;p21 = np.copy(plain0&0x0000000000200000)>>21;p20 = np.copy(plain0&0x0000000000100000)>>20;
      p19 = np.copy(plain0&0x0000000000080000)>>19;p18 = np.copy(plain0&0x0000000000040000)>>18;p17 = np.copy(plain0&0x0000000000020000)>>17;p16 = np.copy(plain0&0x0000000000010000)>>16;
      p15 = np.copy(plain0&0x0000000000008000)>>15;p14 = np.copy(plain0&0x0000000000004000)>>14;p13 = np.copy(plain0&0x0000000000002000)>>13;p12 = np.copy(plain0&0x0000000000001000)>>12;
      p11 = np.copy(plain0&0x0000000000000800)>>11;p10 = np.copy(plain0&0x0000000000000400)>>10;p9 = np.copy(plain0&0x0000000000000200)>>9;p8 = np.copy(plain0&0x0000000000000100)>>8;
      p7 = np.copy(plain0&0x0000000000000080)>>7;p6 = np.copy(plain0&0x0000000000000040)>>6;p5 = np.copy(plain0&0x0000000000000020)>>5;p4 = np.copy(plain0&0x0000000000000010)>>4;
      p3 = np.copy(plain0&0x0000000000000008)>>3;p2 = np.copy(plain0&0x0000000000000004)>>2;p1 = np.copy(plain0&0x0000000000000002)>>1;p0 = np.copy(plain0&0x0000000000000001);
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
      p54 = np.copy(p63^p59*p50^p48*IR[0]^k0);#Additional conditions
      #Additional conditions
      p24 = np.copy(p37^p32*p20^p13*p8^k1^1)#c(4,5)
      p21 = np.copy(p34^p29*p17^k3^1)#c(5,5)
      l39 = np.copy(p63^p54^p59*p50^p48*IR[0]^k0);
      p15 = np.copy(p28^p23*p11^p4*l39^k7^1)#c(7,5)
      p62 = np.copy(p47^p53^k0);#c(8,0)

      l39 = np.copy(p63^p54^p59*p50^p48*IR[0]^k0);
      l44 = np.copy(p58^p54*p45^p43*IR[1]^k2);
      s31 = np.copy(p32^p19^p27*p15^p8*p3^k5)
      s40 = np.copy(p23^p10^l39*l44^k11)
      p19 = np.copy(p32^p27*p15^p8*p3^k5^s40^1)#c(9,3)
      
      s27 = np.copy(p36^p23^k1)
      s29 = np.copy(p34^p21^p29*p17^k3)
      l48 = np.copy(p54^p45^p50*p41^p39*IR[3]^k6);
      l53 = np.copy(p40^p45*s27^s29*IR[4]^k8);
      p14 = np.copy(p1^l48*l53^k17)#c(12,3)
      
      l43 = np.copy(p59^p50^p44*IR[1]^k2);
      l48 = np.copy(p54^p45^p50*p41^p39*IR[3]^k6);
      p6 = np.copy(p19^p14*p2^l43*l48^k13)#c(10,5)
      
      s27 = np.copy(p36^p23^k1)
      s28 = np.copy(p35^p11*p6^k3)
      s33 = np.copy(p30^p17^p25*p13^p6*p1^k5)
      l41 = np.copy(p61^p52^p57*p48^k0);
      l52 = np.copy(p50^s28*IR[4]^k8);
      l57 = np.copy(p45^s27^s33*IR[6]^k12);
      p61 = np.copy(p10^(p52^p57*p48^k0)^l52*l57^k19)#c(13,5)
      
      s28 = np.copy(p35^p11*p6^k3)
      s30 = np.copy(p33^p20^k3)
      p33 = np.copy(p48^p39^p44*s28^(p20^k3)^k10);#Additional conditions
      
      l39 = np.copy(p63^p54^p59*p50^p48*IR[0]^k0);
      l44 = np.copy(p58^p54*p45^p43*IR[1]^k2);
      s26 = np.copy(p37^p24^p32*p20^p13*p8^k1)
      s27 = np.copy(p36^p23^k1)
      s28 = np.copy(p35^p11*p6^k3)
      s30 = np.copy(p33^p20^k3)
      s31 = np.copy(p32^p19^p27*p15^p8*p3^k5)
      s35 = np.copy(p28^p15^p23*p11^p4*l39^k7)
      s36 = np.copy(p27^p14^k7)
      s40 = np.copy(p23^p10^l39*l44^k11)
      l42 = np.copy(p60^p51^p56*p47^p45*IR[1]^k2);
      l50 = np.copy(p52^p43^p48*p39^s26*IR[3]^k6);
      l54 = np.copy(p48^p39^p44*s28^s30*IR[5]^k10);
      l61 = np.copy(s31^s26*s35^k14);
      l66 = np.copy(s27^s36^s31*s40^k18);
      p43 = np.copy(p1^(p52^p48*p39^s26*IR[3]^k6)^l42*l54^l61*l66^k25)#c(16,5)
      
      s25 = np.copy(p38^p25^p33*p21^k1);
      s26 = np.copy(p37^p24^p32*p20^p13*p8^k1)
      s27 = np.copy(p36^p23^k1)
      s30 = np.copy(p33^p20^k3)
      s31 = np.copy(p32^p19^p27*p15^p8*p3^k5)
      s32 = np.copy(p31^p18^p26*p14^k5)
      s34 = np.copy(p29^p16^p24*p12^k7)
      l41 = np.copy(p61^p52^p46*IR[0]^k0);
      l43 = np.copy(p59^p50^p44*IR[1]^k2);
      l44 = np.copy(p58^p49^p54*p45^p43*IR[1]^k2);
      l45 = np.copy(p57^p48^p53*p44^p42*IR[2]^k4);
      l47 = np.copy(p55^p46^p51*p42^p40*IR[2]^k4);
      l49 = np.copy(p53^p44^s25*IR[3]^k6);
      l51 = np.copy(p51^p42^p47*s25^s27*IR[4]^k8);
      l56 = np.copy(p46^s26^p42*s30^s32*IR[5]^k10);
      s35 = np.copy(p28^p15^p23*p11^p4*l39^k7)
      s39 = np.copy(p24^p11^p0*l43^k9)
      l60 = np.copy(p42^s30^s25*s34^k14);
      l61 = np.copy(p41^s31^s26*s35^k14);
      l65 = np.copy(s26^s35^s30*s39^k16);
      s48 = np.copy(p15^p2^l47*l52^k15)
      s52 = np.copy(p11^p6*l44^l51*l56^k19)
      s57 = np.copy(p6^l45^p1*l49^l56*l61^k21)
      s61 = np.copy(p2^l49^l41*l53^l60*l65^k25)
      p57 = np.copy(s48^(p6^(p48^p53*p44^p42*IR[2]^k4)^p1*l49^l56*l61^k21)^s52*s61^k32);#c(21,2)
      
      s25 = np.copy(p38^p25^p33*p21^p14*p9^k1);
      s26 = np.copy(p37^p24^p32*p20^p13*p8^k1)
      s27 = np.copy(p36^p23^p31*p19^p12*p7^k1)
      s28 = np.copy(p35^p22^p30*p18^p11*p6^k3)
      s29 = np.copy(p34^p21^p29*p17^p10*p5^k3)
      s30 = np.copy(p33^p20^p28*p16^p9*p4^k3)
      s31 = np.copy(p32^p19^p27*p15^p8*p3^k5)
      s32 = np.copy(p31^p18^p26*p14^p7*p2^k5)
      s33 = np.copy(p30^p17^p25*p13^p6*p1^k5)
      s34 = np.copy(p29^p16^p24*p12^p5*p0^k7)
      l39 = np.copy(p63^p54^p59*p50^p48*IR[0]^k0);
      l40 = np.copy(p62^p53^p58*p49^p47*IR[0]^k0);
      l41 = np.copy(p61^p52^p57*p48^p46*IR[0]^k0);
      l42 = np.copy(p60^p51^p56*p47^p45*IR[1]^k2);
      l43 = np.copy(p59^p50^p55*p46^p44*IR[1]^k2);
      l44 = np.copy(p58^p49^p54*p45^p43*IR[1]^k2);
      l45 = np.copy(p57^p48^p53*p44^p42*IR[2]^k4);
      l46 = np.copy(p56^p47^p52*p43^p41*IR[2]^k4);
      l47 = np.copy(p55^p46^p51*p42^p40*IR[2]^k4);
      l48 = np.copy(p54^p45^p50*p41^p39*IR[3]^k6);
      l49 = np.copy(p53^p44^p49*p40^s25*IR[3]^k6);
      l50 = np.copy(p52^p43^p48*p39^s26*IR[3]^k6); 
      l51 = np.copy(p51^p42^p47*s25^s27*IR[4]^k8);
      l52 = np.copy(p50^p41^p46*s26^s28*IR[4]^k8);
      l53 = np.copy(p49^p40^p45*s27^s29*IR[4]^k8);
      l55 = np.copy(p47^s25^p43*s29^s31*IR[5]^k10);
      l57 = np.copy(p45^s27^p41*s31^s33*IR[6]^k12);
      l58 = np.copy(p44^s28^p40*s32^s34*IR[6]^k12);
      s35 = np.copy(p28^p15^p23*p11^p4*l39^k7)
      s36 = np.copy(p27^p14^p22*p10^p3*l40^k7)
      s37 = np.copy(p26^p13^p21*p9^p2*l41^k9)
      s38 = np.copy(p25^p12^p20*p8^p1*l42^k9)
      s39 = np.copy(p24^p11^p19*p7^p0*l43^k9)
      s40 = np.copy(p23^p10^p18*p6^l39*l44^k11)
      s41 = np.copy(p22^p9^p17*p5^l40*l45^k11)
      s42 = np.copy(p21^p8^p16*p4^l41*l46^k11)
      s44 = np.copy(p19^p6^p14*p2^l43*l48^k13)
      s45 = np.copy(p18^p5^p13*p1^l44*l49^k13)
      s46 = np.copy(p17^p4^p12*p0^l45*l50^k15)
      s47 = np.copy(p16^p3^p11*l39^l46*l51^k15)
      s48 = np.copy(p15^p2^p10*l40^l47*l52^k15) 
      s49 = np.copy(p14^p1^p9*l41^l48*l53^k17) 
      s51 = np.copy(p12^l39^p7*l43^l50*l55^k17) 
      s53 = np.copy(p10^l41^p5*l45^l52*l57^k19) 
      l59 = np.copy(p43^s29^p39*s33^s35*IR[6]^k12);
      l61 = np.copy(p41^s31^s26*s35^s37*IR[7]^k14);
      l62 = np.copy(p40^s32^s27*s36^s38*IR[7]^k14);
      l63 = np.copy(p39^s33^s28*s37^s39*IR[8]^k16);
      l65 = np.copy(s26^s35^s30*s39^s41*IR[8]^k16);
      l66 = np.copy(s27^s36^s31*s40^s42*IR[9]^k18);
      l70 = np.copy(s31^s40^s35*s44^s46*IR[10]^k20);
      l71 = np.copy(s32^s41^s36*s45^s47*IR[10]^k20);
      l72 = np.copy(s33^s42^s37*s46^s48*IR[11]^k22);
      l75 = np.copy(s36^s45^s40*s49^s51*IR[12]^k24);
      l77 = np.copy(s38^s47^s42*s51^s53*IR[12]^k24);
      l46 = np.copy(p56^p47^p52*p43^p41*IR[2]^k4);
      s58 = np.copy(p5^l46^p0*l50^l57*l62^k23)
      s62 = np.copy(p1^l50^l42*l54^l61*l66^k25)
      s67 = np.copy(l42^l55^l47*l59^l66*l71^k29)
      s71 = np.copy(l46^l59^l51*l63^l70*l75^k31)
      s73 = np.copy(l48^l61^l53*l65^l72*l77^k33)
      p60 = np.copy(s58^((p51^p56*p47^p45*IR[1]^k2)^l55^l47*l59^l66*l71^k29)^s62*s71^s73*IR[19]^k38);
      
      
      p62=p62<<62;p61=p61<<61;p60=p60<<60;p57=p57<<57;p54=p54<<54;p43=p43<<43;p33=p33<<33;p24=p24<<24;p21=p21<<21;p19=p19<<19;p15=p15<<15;
      p14=p14<<14;p6=p6<<6;
      plain0 = np.copy(plain0&0x8DBFF7FDFED73FBF^p62^p61^p60^p57^p54^p43^p33^p24^p21^p19^p15^p14^p6);
      plain1 = plain0 ^ diff
      myKATAN = KATAN(keys, 64, nr)
      ctdata0 = myKATAN.enc(plain0)
      ctdata1 = myKATAN.enc(plain1)
      ctdata = ctdata0^ctdata1
      #print(ctdata)
      cta+=[ctdata0] 
      ctb+=[ctdata1]
    return (cta,ctb)
'''
n=10
nr=25
keys = np.frombuffer(urandom(10*n),dtype=np.uint16).reshape(5,-1);
make_structure(n, nr, keys)
'''
# Decrypt the last 9 rounds
def dec_rounds(ctdata0,ctdata1,ck1):
    k = np.copy(ck1);
    k74=np.copy(k&0x8000)>>15;  
    k75=np.copy(k&0x4000)>>14;
    k76=np.copy(k&0x2000)>>13;
    k77=np.copy(k&0x1000)>>12;
    k78=np.copy(k&0x800)>>11;
    k79=np.copy(k&0x400)>>10;
    k80=np.copy(k&0x200)>>9;
    k81=np.copy(k&0x100)>>8;
    k82=np.copy(k&0x80)>>7;
    k83=np.copy(k&0x40)>>6;
    k84=np.copy(k&0x20)>>5;
    k85=np.copy(k&0x10)>>4;
    k86=np.copy(k&0x8)>>3;
    k87=np.copy(k&0x4)>>2;
    k88=np.copy(k&0x2)>>1;
    k89=np.copy(k&0x1);
    # Ciphertext ctdata0 register
    s135 = np.copy(ctdata0)>>63;
    s135 = np.absolute(s135)
    s136 = np.copy(ctdata0&0x4000000000000000)>>62;s137 = np.copy(ctdata0&0x2000000000000000)>>61;s138 = np.copy(ctdata0&0x1000000000000000)>>60;
    s139 = np.copy(ctdata0&0x0800000000000000)>>59;s140 = np.copy(ctdata0&0x0400000000000000)>>58;s141 = np.copy(ctdata0&0x0200000000000000)>>57;s142 = np.copy(ctdata0&0x0100000000000000)>>56;
    s143 = np.copy(ctdata0&0x0080000000000000)>>55;s144 = np.copy(ctdata0&0x0040000000000000)>>54;s145 = np.copy(ctdata0&0x0020000000000000)>>53;s146 = np.copy(ctdata0&0x0010000000000000)>>52;
    s147 = np.copy(ctdata0&0x0008000000000000)>>51;s148 = np.copy(ctdata0&0x0004000000000000)>>50;s149 = np.copy(ctdata0&0x0002000000000000)>>49;s150 = np.copy(ctdata0&0x0001000000000000)>>48;
    s151 = np.copy(ctdata0&0x0000800000000000)>>47;s152 = np.copy(ctdata0&0x0000400000000000)>>46;s153 = np.copy(ctdata0&0x0000200000000000)>>45;s154 = np.copy(ctdata0&0x0000100000000000)>>44;
    s155 = np.copy(ctdata0&0x0000080000000000)>>43;s156 = np.copy(ctdata0&0x0000040000000000)>>42;s157 = np.copy(ctdata0&0x0000020000000000)>>41;s158 = np.copy(ctdata0&0x0000010000000000)>>40;
    s159 = np.copy(ctdata0&0x0000008000000000)>>39;l135 = np.copy(ctdata0&0x0000004000000000)>>38;l136 = np.copy(ctdata0&0x0000002000000000)>>37;l137 = np.copy(ctdata0&0x0000001000000000)>>36;
    l138 = np.copy(ctdata0&0x0000000800000000)>>35;l139 = np.copy(ctdata0&0x0000000400000000)>>34;l140 = np.copy(ctdata0&0x0000000200000000)>>33;l141 = np.copy(ctdata0&0x0000000100000000)>>32;
    l142 = np.copy(ctdata0&0x0000000080000000)>>31;l143 = np.copy(ctdata0&0x0000000040000000)>>30;l144 = np.copy(ctdata0&0x0000000020000000)>>29;l145 = np.copy(ctdata0&0x0000000010000000)>>28;
    l146 = np.copy(ctdata0&0x0000000008000000)>>27;l147 = np.copy(ctdata0&0x0000000004000000)>>26;l148 = np.copy(ctdata0&0x0000000002000000)>>25;l149 = np.copy(ctdata0&0x0000000001000000)>>24;
    l150 = np.copy(ctdata0&0x0000000000800000)>>23;l151 = np.copy(ctdata0&0x0000000000400000)>>22;l152 = np.copy(ctdata0&0x0000000000200000)>>21;l153 = np.copy(ctdata0&0x0000000000100000)>>20;
    l154 = np.copy(ctdata0&0x0000000000080000)>>19;l155 = np.copy(ctdata0&0x0000000000040000)>>18;l156 = np.copy(ctdata0&0x0000000000020000)>>17;l157 = np.copy(ctdata0&0x0000000000010000)>>16;
    l158 = np.copy(ctdata0&0x0000000000008000)>>15;l159 = np.copy(ctdata0&0x0000000000004000)>>14;l160 = np.copy(ctdata0&0x0000000000002000)>>13;l161 = np.copy(ctdata0&0x0000000000001000)>>12;
    l162 = np.copy(ctdata0&0x0000000000000800)>>11;l163 = np.copy(ctdata0&0x0000000000000400)>>10;l164 = np.copy(ctdata0&0x0000000000000200)>>9;l165 = np.copy(ctdata0&0x0000000000000100)>>8;
    l166 = np.copy(ctdata0&0x0000000000000080)>>7;l167 = np.copy(ctdata0&0x0000000000000040)>>6;l168 = np.copy(ctdata0&0x0000000000000020)>>5;l169 = np.copy(ctdata0&0x0000000000000010)>>4;
    l170 = np.copy(ctdata0&0x0000000000000008)>>3;l171 = np.copy(ctdata0&0x0000000000000004)>>2;l172 = np.copy(ctdata0&0x0000000000000002)>>1;l173 = np.copy(ctdata0&0x0000000000000001);
    # Ciphertext ctdata1 register
    s_135 = np.copy(ctdata1)>>63;
    s_135 = np.absolute(s_135)
    s_136 = np.copy(ctdata1&0x4000000000000000)>>62;s_137 = np.copy(ctdata1&0x2000000000000000)>>61;s_138 = np.copy(ctdata1&0x1000000000000000)>>60;
    s_139 = np.copy(ctdata1&0x0800000000000000)>>59;s_140 = np.copy(ctdata1&0x0400000000000000)>>58;s_141 = np.copy(ctdata1&0x0200000000000000)>>57;s_142 = np.copy(ctdata1&0x0100000000000000)>>56;
    s_143 = np.copy(ctdata1&0x0080000000000000)>>55;s_144 = np.copy(ctdata1&0x0040000000000000)>>54;s_145 = np.copy(ctdata1&0x0020000000000000)>>53;s_146 = np.copy(ctdata1&0x0010000000000000)>>52;
    s_147 = np.copy(ctdata1&0x0008000000000000)>>51;s_148 = np.copy(ctdata1&0x0004000000000000)>>50;s_149 = np.copy(ctdata1&0x0002000000000000)>>49;s_150 = np.copy(ctdata1&0x0001000000000000)>>48;
    s_151 = np.copy(ctdata1&0x0000800000000000)>>47;s_152 = np.copy(ctdata1&0x0000400000000000)>>46;s_153 = np.copy(ctdata1&0x0000200000000000)>>45;s_154 = np.copy(ctdata1&0x0000100000000000)>>44;
    s_155 = np.copy(ctdata1&0x0000080000000000)>>43;s_156 = np.copy(ctdata1&0x0000040000000000)>>42;s_157 = np.copy(ctdata1&0x0000020000000000)>>41;s_158 = np.copy(ctdata1&0x0000010000000000)>>40;
    s_159 = np.copy(ctdata1&0x0000008000000000)>>39;l_135 = np.copy(ctdata1&0x0000004000000000)>>38;l_136 = np.copy(ctdata1&0x0000002000000000)>>37;l_137 = np.copy(ctdata1&0x0000001000000000)>>36;
    l_138 = np.copy(ctdata1&0x0000000800000000)>>35;l_139 = np.copy(ctdata1&0x0000000400000000)>>34;l_140 = np.copy(ctdata1&0x0000000200000000)>>33;l_141 = np.copy(ctdata1&0x0000000100000000)>>32;
    l_142 = np.copy(ctdata1&0x0000000080000000)>>31;l_143 = np.copy(ctdata1&0x0000000040000000)>>30;l_144 = np.copy(ctdata1&0x0000000020000000)>>29;l_145 = np.copy(ctdata1&0x0000000010000000)>>28;
    l_146 = np.copy(ctdata1&0x0000000008000000)>>27;l_147 = np.copy(ctdata1&0x0000000004000000)>>26;l_148 = np.copy(ctdata1&0x0000000002000000)>>25;l_149 = np.copy(ctdata1&0x0000000001000000)>>24;
    l_150 = np.copy(ctdata1&0x0000000000800000)>>23;l_151 = np.copy(ctdata1&0x0000000000400000)>>22;l_152 = np.copy(ctdata1&0x0000000000200000)>>21;l_153 = np.copy(ctdata1&0x0000000000100000)>>20;
    l_154 = np.copy(ctdata1&0x0000000000080000)>>19;l_155 = np.copy(ctdata1&0x0000000000040000)>>18;l_156 = np.copy(ctdata1&0x0000000000020000)>>17;l_157 = np.copy(ctdata1&0x0000000000010000)>>16;
    l_158 = np.copy(ctdata1&0x0000000000008000)>>15;l_159 = np.copy(ctdata1&0x0000000000004000)>>14;l_160 = np.copy(ctdata1&0x0000000000002000)>>13;l_161 = np.copy(ctdata1&0x0000000000001000)>>12;
    l_162 = np.copy(ctdata1&0x0000000000000800)>>11;l_163 = np.copy(ctdata1&0x0000000000000400)>>10;l_164 = np.copy(ctdata1&0x0000000000000200)>>9;l_165 = np.copy(ctdata1&0x0000000000000100)>>8;
    l_166 = np.copy(ctdata1&0x0000000000000080)>>7;l_167 = np.copy(ctdata1&0x0000000000000040)>>6;l_168 = np.copy(ctdata1&0x0000000000000020)>>5;l_169 = np.copy(ctdata1&0x0000000000000010)>>4;
    l_170 = np.copy(ctdata1&0x0000000000000008)>>3;l_171 = np.copy(ctdata1&0x0000000000000004)>>2;l_172 = np.copy(ctdata1&0x0000000000000002)>>1;l_173 = np.copy(ctdata1&0x0000000000000001);
     
    # Ciphertext assigns the difference
    s134 = np.copy(l173^s143^s138*s147^s149*IR[69]^k88);s_134 = np.copy(l_173^s_143^s_138*s_147^s_149*IR[69]^k88);
    s133 = np.copy(l172^s142^s137*s146^s148*IR[69]^k88);s_133 = np.copy(l_172^s_142^s_137*s_146^s_148*IR[69]^k88);
    s132 = np.copy(l171^s141^s136*s145^s147*IR[69]^k88);s_132 = np.copy(l_171^s_141^s_136*s_145^s_147*IR[69]^k88);
    s131 = np.copy(l170^s140^s135*s144^s146*IR[68]^k86);s_131 = np.copy(l_170^s_140^s_135*s_144^s_146*IR[68]^k86);
    s130 = np.copy(l169^s139^s134*s143^s145*IR[68]^k86);s_130 = np.copy(l_169^s_139^s_134*s_143^s_145*IR[68]^k86);
    s129 = np.copy(l168^s138^s133*s142^s144*IR[68]^k86);s_129 = np.copy(l_168^s_138^s_133*s_142^s_144*IR[68]^k86);
    s128 = np.copy(l167^s137^s132*s141^s143*IR[67]^k84);s_128 = np.copy(l_167^s_137^s_132*s_141^s_143*IR[67]^k84);
    s127 = np.copy(l166^s136^s131*s140^s142*IR[67]^k84);s_127 = np.copy(l_166^s_136^s_131*s_140^s_142*IR[67]^k84);
    s126 = np.copy(l165^s135^s130*s139^s141*IR[67]^k84);s_126 = np.copy(l_165^s_135^s_130*s_139^s_141*IR[67]^k84);
    s125 = np.copy(l164^s134^s129*s138^s140*IR[66]^k82);s_125 = np.copy(l_164^s_134^s_129*s_138^s_140*IR[66]^k82);
    s124 = np.copy(l163^s133^s128*s137^s139*IR[66]^k82);s_124 = np.copy(l_163^s_133^s_128*s_137^s_139*IR[66]^k82);
    s123 = np.copy(l162^s132^s127*s136^s138*IR[66]^k82);s_123 = np.copy(l_162^s_132^s_127*s_136^s_138*IR[66]^k82);
    s122 = np.copy(l161^s131^s126*s135^s137*IR[65]^k80);s_122 = np.copy(l_161^s_131^s_126*s_135^s_137*IR[65]^k80);
    s121 = np.copy(l160^s130^s125*s134^s136*IR[65]^k80);s_121 = np.copy(l_160^s_130^s_125*s_134^s_136*IR[65]^k80);
    s120 = np.copy(l159^s129^s124*s133^s135*IR[65]^k80);s_120 = np.copy(l_159^s_129^s_124*s_133^s_135*IR[65]^k80);
    s119 = np.copy(l158^s128^s123*s132^s134*IR[64]^k78);s_119 = np.copy(l_158^s_128^s_123*s_132^s_134*IR[64]^k78);
    s118 = np.copy(l157^s127^s122*s131^s133*IR[64]^k78);s_118 = np.copy(l_157^s_127^s_122*s_131^s_133*IR[64]^k78);
    s117 = np.copy(l156^s126^s121*s130^s132*IR[64]^k78);s_117 = np.copy(l_156^s_126^s_121*s_130^s_132*IR[64]^k78);
    s116 = np.copy(l155^s125^s120*s129^s131*IR[63]^k76);s_116 = np.copy(l_155^s_125^s_120*s_129^s_131*IR[63]^k76);
    s115 = np.copy(l154^s124^s119*s128^s130*IR[63]^k76);s_115 = np.copy(l_154^s_124^s_119*s_128^s_130*IR[63]^k76);
    s114 = np.copy(l153^s123^s118*s127^s129*IR[63]^k76);s_114 = np.copy(l_153^s_123^s_118*s_127^s_129*IR[63]^k76);
    s113 = np.copy(l152^s122^s117*s126^s128*IR[62]^k74);s_113 = np.copy(l_152^s_122^s_117*s_126^s_128*IR[62]^k74);
    s112 = np.copy(l151^s121^s116*s125^s127*IR[62]^k74);s_112 = np.copy(l_151^s_121^s_116*s_125^s_127*IR[62]^k74);
     
    l134 = np.copy(s159^l147^l139*l151^l158*l163^k89);l_134 = np.copy(s_159^l_147^l_139*l_151^l_158*l_163^k89);
    l133 = np.copy(s158^l146^l138*l150^l157*l162^k89);l_133 = np.copy(s_158^l_146^l_138*l_150^l_157*l_162^k89);
    l132 = np.copy(s157^l145^l137*l149^l156*l161^k89);l_132 = np.copy(s_157^l_145^l_137*l_149^l_156*l_161^k89);
    l131 = np.copy(s156^l144^l136*l148^l155*l160^k87);l_131 = np.copy(s_156^l_144^l_136*l_148^l_155*l_160^k87);
    l130 = np.copy(s155^l143^l135*l147^l154*l159^k87);l_130 = np.copy(s_155^l_143^l_135*l_147^l_154*l_159^k87);
    l129 = np.copy(s154^l142^l134*l146^l153*l158^k87);l_129 = np.copy(s_154^l_142^l_134*l_146^l_153*l_158^k87);
    l128 = np.copy(s153^l141^l133*l145^l152*l157^k85);l_128 = np.copy(s_153^l_141^l_133*l_145^l_152*l_157^k85);
    l127 = np.copy(s152^l140^l132*l144^l151*l156^k85);l_127 = np.copy(s_152^l_140^l_132*l_144^l_151*l_156^k85);
    l126 = np.copy(s151^l139^l131*l143^l150*l155^k85);l_126 = np.copy(s_151^l_139^l_131*l_143^l_150*l_155^k85);
    l125 = np.copy(s150^l138^l130*l142^l149*l154^k83);l_125 = np.copy(s_150^l_138^l_130*l_142^l_149*l_154^k83);
    l124 = np.copy(s149^l137^l129*l141^l148*l153^k83);l_124 = np.copy(s_149^l_137^l_129*l_141^l_148*l_153^k83);
    l123 = np.copy(s148^l136^l128*l140^l147*l152^k83);l_123 = np.copy(s_148^l_136^l_128*l_140^l_147*l_152^k83);
    l122 = np.copy(s147^l135^l127*l139^l146*l151^k81);l_122 = np.copy(s_147^l_135^l_127*l_139^l_146*l_151^k81);
    l121 = np.copy(s146^l134^l126*l138^l145*l150^k81);l_121 = np.copy(s_146^l_134^l_126*l_138^l_145*l_150^k81);
    l120 = np.copy(s145^l133^l125*l137^l144*l149^k81);l_120 = np.copy(s_145^l_133^l_125*l_137^l_144*l_149^k81);
    l119 = np.copy(s144^l132^l124*l136^l143*l148^k79);l_119 = np.copy(s_144^l_132^l_124*l_136^l_143*l_148^k79);
    l118 = np.copy(s143^l131^l123*l135^l142*l147^k79);l_118 = np.copy(s_143^l_131^l_123*l_135^l_142*l_147^k79);
    l117 = np.copy(s142^l130^l122*l134^l141*l146^k79);l_117 = np.copy(s_142^l_130^l_122*l_134^l_141*l_146^k79);
    l116 = np.copy(s141^l129^l121*l133^l140*l145^k77);l_116 = np.copy(s_141^l_129^l_121*l_133^l_140*l_145^k77);
    l115 = np.copy(s140^l128^l120*l132^l139*l144^k77);l_115 = np.copy(s_140^l_128^l_120*l_132^l_139*l_144^k77);
    l114 = np.copy(s139^l127^l119*l131^l138*l143^k77);l_114 = np.copy(s_139^l_127^l_119*l_131^l_138*l_143^k77);
    l113 = np.copy(s138^l126^l118*l130^l137*l142^k75);l_113 = np.copy(s_138^l_126^l_118*l_130^l_137*l_142^k75);
     
    #Assignment of the s register
    
    c39 = np.copy(s132^s_132);
    c40 = np.copy(s131^s_131);
    c41 = np.copy(s130^s_130);
    c42 = np.copy(s129^s_129);
    c43 = np.copy(s128^s_128);
    c44 = np.copy(s127^s_127);
    c45 = np.copy(s126^s_126);
    c46 = np.copy(s125^s_125);
    c47 = np.copy(s124^s_124);
    c48 = np.copy(s123^s_123);
    c49 = np.copy(s122^s_122);
    c50 = np.copy(s121^s_121);
    c51 = np.copy(s120^s_120);
    c52 = np.copy(s119^s_119);
    c53 = np.copy(s118^s_118);
    c54 = np.copy(s117^s_117);
    c55 = np.copy(s116^s_116);
    c56 = np.copy(s115^s_115);
    c57 = np.copy(s114^s_114);
    c58 = np.copy(s113^s_113);
    c59 = np.copy(s112^s_112);
    c60 = np.copy((l150^s120^s115*s124^s126*IR[62])^(l_150^s_120^s_115*s_124^s_126*IR[62]));
    c61 = np.copy((l149^s119^s114*s123^s125*IR[61])^(l_149^s_119^s_114*s_123^s_125*IR[61]));
    c62 = np.copy((l148^s118^s113*s122^s124*IR[61])^(l_148^s_118^s_113*s_122^s_124*IR[61]));
    c63 = np.copy((l147^s117^s112*s121^s123*IR[61])^(l_147^s_117^s_112*s_121^s_123*IR[61]));
    #Assignment of the l register
    c0 = np.copy(l146^l_146);c1 = np.copy(l145^l_145);c2 = np.copy(l144^l_144);c3 = np.copy(l143^l_143);
    c4 = np.copy(l142^l_142);c5 = np.copy(l141^l_141);c6 = np.copy(l140^l_140);c7 = np.copy(l139^l_139);
    c8 = np.copy(l138^l_138);c9 = np.copy(l137^l_137);c10 = np.copy(l136^l_136);c11 = np.copy(l135^l_135);
    c12 = np.copy(l134^l_134);c13 = np.copy(l133^l_133);c14 = np.copy(l132^l_132);c15 = np.copy(l131^l_131);
    c16 = np.copy(l130^l_130);c17 = np.copy(l129^l_129);c18 = np.copy(l128^l_128);c19 = np.copy(l127^l_127);
    c20 = np.copy(l126^l_126);c21 = np.copy(l125^l_125);
    c22 = np.copy(l124^l_124);
    c23 = np.copy(l123^l_123);
    c24 = np.copy(l122^l_122);
    c25 = np.copy(l121^l_121);
    c26 = np.copy(l120^l_120);
    c27 = np.copy(l119^l_119);
    c28 = np.copy(l118^l_118);
    c29 = np.copy(l117^l_117);
    c30 = np.copy(l116^l_116);
    c31 = np.copy(l115^l_115);
    c32 = np.copy(l114^l_114);
    c33 = np.copy(l113^l_113);
    c34 = np.copy((s137^l125^l117*l129^l136*l141)^(s_137^l_125^l_117*l_129^l_136*l_141));
    c35 = np.copy((s136^l124^l116*l128^l135*l140)^(s_136^l_124^l_116*l_128^l_135*l_140));
    c36 = np.copy((s135^l123^l115*l127^l134*l139)^(s_135^l_123^l_115*l_127^l_134*l_139));
    c37 = np.copy((s134^l122^l114*l126^l133*l138)^(s_134^l_122^l_114*l_126^l_133*l_138));
    c38 = np.copy((s133^l121^l113*l125^l132*l137)^(s_133^l_121^l_113*l_125^l_132*l_137));
    
    #Differential register reassignment
    c63=c63<<63;c62=c62<<62;c61=c61<<61;c60=c60<<60;c59=c59<<59;c58=c58<<58;c57=c57<<57;c56=c56<<56;
    c55=c55<<55;c54=c54<<54;c53=c53<<53;c52=c52<<52;c51=c51<<51;c50=c50<<50;c49=c49<<49;c48=c48<<48;
    c47=c47<<47;c46=c46<<46;c45=c45<<45;c44=c44<<44;c43=c43<<43;c42=c42<<42;c41=c41<<41;c40=c40<<40;
    c39=c39<<39;c38=c38<<38;c37=c37<<37;c36=c36<<36;c35=c35<<35;c34=c34<<34;c33=c33<<33;c32=c32<<32;
    c31=c31<<31;c30=c30<<30;c29=c29<<29;c28=c28<<28;c27=c27<<27;c26=c26<<26;c25=c25<<25;c24=c24<<24;
    c23=c23<<23;c22=c22<<22;c21=c21<<21;c20=c20<<20;c19=c19<<19;c18=c18<<18;c17=c17<<17;c16=c16<<16;
    c15=c15<<15;c14=c14<<14;c13=c13<<13;c12=c12<<12;c11=c11<<11;c10=c10<<10;c9=c9<<9;c8=c8<<8;
    c7=c7<<7;c6=c6<<6;c5=c5<<5;c4=c4<<4;c3=c3<<3;c2=c2<<2;c1=c1<<1;c0=c0;
    ctdata=0x0^(c63^c62^c61^c60^c59^c58^c57^c56^c55^c54^c53^c52^c51^c50^c49^c48^c47^c46^c45^c44^c43^c42^c41^c40^c39^c38^c37^c36^c35^c34^c33^c32^c31^c30^c29^c28^c27^c26^c25^c24^c23^c22^c21^c20^c19^c18^c17^c16^c15^c14^c13^c12^c11^c10^c9^c8^c7^c6^c5^c4^c3^c2^c1^c0); 
    return ctdata

# 7 rounds of decryption using the guessed key
def dec_rounds1(ctdata0,ctdata1,ck1):
    k = np.copy(ck1);
    k76=np.copy(k&0x2000)>>13;
    k77=np.copy(k&0x1000)>>12;
    k78=np.copy(k&0x800)>>11;
    k79=np.copy(k&0x400)>>10;
    k80=np.copy(k&0x200)>>9;
    k81=np.copy(k&0x100)>>8;
    k82=np.copy(k&0x80)>>7;
    k83=np.copy(k&0x40)>>6;
    k84=np.copy(k&0x20)>>5;
    k85=np.copy(k&0x10)>>4;
    k86=np.copy(k&0x8)>>3;
    k87=np.copy(k&0x4)>>2;
    k88=np.copy(k&0x2)>>1;
    k89=np.copy(k&0x1);
    s135 = np.copy(ctdata0)>>63;
    s135 = np.absolute(s135)
    s136 = np.copy(ctdata0&0x4000000000000000)>>62;s137 = np.copy(ctdata0&0x2000000000000000)>>61;s138 = np.copy(ctdata0&0x1000000000000000)>>60;
    s139 = np.copy(ctdata0&0x0800000000000000)>>59;s140 = np.copy(ctdata0&0x0400000000000000)>>58;s141 = np.copy(ctdata0&0x0200000000000000)>>57;s142 = np.copy(ctdata0&0x0100000000000000)>>56;
    s143 = np.copy(ctdata0&0x0080000000000000)>>55;s144 = np.copy(ctdata0&0x0040000000000000)>>54;s145 = np.copy(ctdata0&0x0020000000000000)>>53;s146 = np.copy(ctdata0&0x0010000000000000)>>52;
    s147 = np.copy(ctdata0&0x0008000000000000)>>51;s148 = np.copy(ctdata0&0x0004000000000000)>>50;s149 = np.copy(ctdata0&0x0002000000000000)>>49;s150 = np.copy(ctdata0&0x0001000000000000)>>48;
    s151 = np.copy(ctdata0&0x0000800000000000)>>47;s152 = np.copy(ctdata0&0x0000400000000000)>>46;s153 = np.copy(ctdata0&0x0000200000000000)>>45;s154 = np.copy(ctdata0&0x0000100000000000)>>44;
    s155 = np.copy(ctdata0&0x0000080000000000)>>43;s156 = np.copy(ctdata0&0x0000040000000000)>>42;s157 = np.copy(ctdata0&0x0000020000000000)>>41;s158 = np.copy(ctdata0&0x0000010000000000)>>40;
    s159 = np.copy(ctdata0&0x0000008000000000)>>39;l135 = np.copy(ctdata0&0x0000004000000000)>>38;l136 = np.copy(ctdata0&0x0000002000000000)>>37;l137 = np.copy(ctdata0&0x0000001000000000)>>36;
    l138 = np.copy(ctdata0&0x0000000800000000)>>35;l139 = np.copy(ctdata0&0x0000000400000000)>>34;l140 = np.copy(ctdata0&0x0000000200000000)>>33;l141 = np.copy(ctdata0&0x0000000100000000)>>32;
    l142 = np.copy(ctdata0&0x0000000080000000)>>31;l143 = np.copy(ctdata0&0x0000000040000000)>>30;l144 = np.copy(ctdata0&0x0000000020000000)>>29;l145 = np.copy(ctdata0&0x0000000010000000)>>28;
    l146 = np.copy(ctdata0&0x0000000008000000)>>27;l147 = np.copy(ctdata0&0x0000000004000000)>>26;l148 = np.copy(ctdata0&0x0000000002000000)>>25;l149 = np.copy(ctdata0&0x0000000001000000)>>24;
    l150 = np.copy(ctdata0&0x0000000000800000)>>23;l151 = np.copy(ctdata0&0x0000000000400000)>>22;l152 = np.copy(ctdata0&0x0000000000200000)>>21;l153 = np.copy(ctdata0&0x0000000000100000)>>20;
    l154 = np.copy(ctdata0&0x0000000000080000)>>19;l155 = np.copy(ctdata0&0x0000000000040000)>>18;l156 = np.copy(ctdata0&0x0000000000020000)>>17;l157 = np.copy(ctdata0&0x0000000000010000)>>16;
    l158 = np.copy(ctdata0&0x0000000000008000)>>15;l159 = np.copy(ctdata0&0x0000000000004000)>>14;l160 = np.copy(ctdata0&0x0000000000002000)>>13;l161 = np.copy(ctdata0&0x0000000000001000)>>12;
    l162 = np.copy(ctdata0&0x0000000000000800)>>11;l163 = np.copy(ctdata0&0x0000000000000400)>>10;l164 = np.copy(ctdata0&0x0000000000000200)>>9;l165 = np.copy(ctdata0&0x0000000000000100)>>8;
    l166 = np.copy(ctdata0&0x0000000000000080)>>7;l167 = np.copy(ctdata0&0x0000000000000040)>>6;l168 = np.copy(ctdata0&0x0000000000000020)>>5;l169 = np.copy(ctdata0&0x0000000000000010)>>4;
    l170 = np.copy(ctdata0&0x0000000000000008)>>3;l171 = np.copy(ctdata0&0x0000000000000004)>>2;l172 = np.copy(ctdata0&0x0000000000000002)>>1;l173 = np.copy(ctdata0&0x0000000000000001);
    s_135 = np.copy(ctdata1)>>63;
    s_135 = np.absolute(s_135)
    s_136 = np.copy(ctdata1&0x4000000000000000)>>62;s_137 = np.copy(ctdata1&0x2000000000000000)>>61;s_138 = np.copy(ctdata1&0x1000000000000000)>>60;
    s_139 = np.copy(ctdata1&0x0800000000000000)>>59;s_140 = np.copy(ctdata1&0x0400000000000000)>>58;s_141 = np.copy(ctdata1&0x0200000000000000)>>57;s_142 = np.copy(ctdata1&0x0100000000000000)>>56;
    s_143 = np.copy(ctdata1&0x0080000000000000)>>55;s_144 = np.copy(ctdata1&0x0040000000000000)>>54;s_145 = np.copy(ctdata1&0x0020000000000000)>>53;s_146 = np.copy(ctdata1&0x0010000000000000)>>52;
    s_147 = np.copy(ctdata1&0x0008000000000000)>>51;s_148 = np.copy(ctdata1&0x0004000000000000)>>50;s_149 = np.copy(ctdata1&0x0002000000000000)>>49;s_150 = np.copy(ctdata1&0x0001000000000000)>>48;
    s_151 = np.copy(ctdata1&0x0000800000000000)>>47;s_152 = np.copy(ctdata1&0x0000400000000000)>>46;s_153 = np.copy(ctdata1&0x0000200000000000)>>45;s_154 = np.copy(ctdata1&0x0000100000000000)>>44;
    s_155 = np.copy(ctdata1&0x0000080000000000)>>43;s_156 = np.copy(ctdata1&0x0000040000000000)>>42;s_157 = np.copy(ctdata1&0x0000020000000000)>>41;s_158 = np.copy(ctdata1&0x0000010000000000)>>40;
    s_159 = np.copy(ctdata1&0x0000008000000000)>>39;l_135 = np.copy(ctdata1&0x0000004000000000)>>38;l_136 = np.copy(ctdata1&0x0000002000000000)>>37;l_137 = np.copy(ctdata1&0x0000001000000000)>>36;
    l_138 = np.copy(ctdata1&0x0000000800000000)>>35;l_139 = np.copy(ctdata1&0x0000000400000000)>>34;l_140 = np.copy(ctdata1&0x0000000200000000)>>33;l_141 = np.copy(ctdata1&0x0000000100000000)>>32;
    l_142 = np.copy(ctdata1&0x0000000080000000)>>31;l_143 = np.copy(ctdata1&0x0000000040000000)>>30;l_144 = np.copy(ctdata1&0x0000000020000000)>>29;l_145 = np.copy(ctdata1&0x0000000010000000)>>28;
    l_146 = np.copy(ctdata1&0x0000000008000000)>>27;l_147 = np.copy(ctdata1&0x0000000004000000)>>26;l_148 = np.copy(ctdata1&0x0000000002000000)>>25;l_149 = np.copy(ctdata1&0x0000000001000000)>>24;
    l_150 = np.copy(ctdata1&0x0000000000800000)>>23;l_151 = np.copy(ctdata1&0x0000000000400000)>>22;l_152 = np.copy(ctdata1&0x0000000000200000)>>21;l_153 = np.copy(ctdata1&0x0000000000100000)>>20;
    l_154 = np.copy(ctdata1&0x0000000000080000)>>19;l_155 = np.copy(ctdata1&0x0000000000040000)>>18;l_156 = np.copy(ctdata1&0x0000000000020000)>>17;l_157 = np.copy(ctdata1&0x0000000000010000)>>16;
    l_158 = np.copy(ctdata1&0x0000000000008000)>>15;l_159 = np.copy(ctdata1&0x0000000000004000)>>14;l_160 = np.copy(ctdata1&0x0000000000002000)>>13;l_161 = np.copy(ctdata1&0x0000000000001000)>>12;
    l_162 = np.copy(ctdata1&0x0000000000000800)>>11;l_163 = np.copy(ctdata1&0x0000000000000400)>>10;l_164 = np.copy(ctdata1&0x0000000000000200)>>9;l_165 = np.copy(ctdata1&0x0000000000000100)>>8;
    l_166 = np.copy(ctdata1&0x0000000000000080)>>7;l_167 = np.copy(ctdata1&0x0000000000000040)>>6;l_168 = np.copy(ctdata1&0x0000000000000020)>>5;l_169 = np.copy(ctdata1&0x0000000000000010)>>4;
    l_170 = np.copy(ctdata1&0x0000000000000008)>>3;l_171 = np.copy(ctdata1&0x0000000000000004)>>2;l_172 = np.copy(ctdata1&0x0000000000000002)>>1;l_173 = np.copy(ctdata1&0x0000000000000001);
     

    s134 = np.copy(l173^s143^s138*s147^s149*IR[69]^k88);s_134 = np.copy(l_173^s_143^s_138*s_147^s_149*IR[69]^k88);
    s133 = np.copy(l172^s142^s137*s146^s148*IR[69]^k88);s_133 = np.copy(l_172^s_142^s_137*s_146^s_148*IR[69]^k88);
    s132 = np.copy(l171^s141^s136*s145^s147*IR[69]^k88);s_132 = np.copy(l_171^s_141^s_136*s_145^s_147*IR[69]^k88);
    s131 = np.copy(l170^s140^s135*s144^s146*IR[68]^k86);s_131 = np.copy(l_170^s_140^s_135*s_144^s_146*IR[68]^k86);
    s130 = np.copy(l169^s139^s134*s143^s145*IR[68]^k86);s_130 = np.copy(l_169^s_139^s_134*s_143^s_145*IR[68]^k86);
    s129 = np.copy(l168^s138^s133*s142^s144*IR[68]^k86);s_129 = np.copy(l_168^s_138^s_133*s_142^s_144*IR[68]^k86);
    s128 = np.copy(l167^s137^s132*s141^s143*IR[67]^k84);s_128 = np.copy(l_167^s_137^s_132*s_141^s_143*IR[67]^k84);
    s127 = np.copy(l166^s136^s131*s140^s142*IR[67]^k84);s_127 = np.copy(l_166^s_136^s_131*s_140^s_142*IR[67]^k84);
    s126 = np.copy(l165^s135^s130*s139^s141*IR[67]^k84);s_126 = np.copy(l_165^s_135^s_130*s_139^s_141*IR[67]^k84);
    s125 = np.copy(l164^s134^s129*s138^s140*IR[66]^k82);s_125 = np.copy(l_164^s_134^s_129*s_138^s_140*IR[66]^k82);
    s124 = np.copy(l163^s133^s128*s137^s139*IR[66]^k82);s_124 = np.copy(l_163^s_133^s_128*s_137^s_139*IR[66]^k82);
    s123 = np.copy(l162^s132^s127*s136^s138*IR[66]^k82);s_123 = np.copy(l_162^s_132^s_127*s_136^s_138*IR[66]^k82);
    s122 = np.copy(l161^s131^s126*s135^s137*IR[65]^k80);s_122 = np.copy(l_161^s_131^s_126*s_135^s_137*IR[65]^k80);
    s121 = np.copy(l160^s130^s125*s134^s136*IR[65]^k80);s_121 = np.copy(l_160^s_130^s_125*s_134^s_136*IR[65]^k80);
    s120 = np.copy(l159^s129^s124*s133^s135*IR[65]^k80);s_120 = np.copy(l_159^s_129^s_124*s_133^s_135*IR[65]^k80);
    s119 = np.copy(l158^s128^s123*s132^s134*IR[64]^k78);s_119 = np.copy(l_158^s_128^s_123*s_132^s_134*IR[64]^k78);
    s118 = np.copy(l157^s127^s122*s131^s133*IR[64]^k78);s_118 = np.copy(l_157^s_127^s_122*s_131^s_133*IR[64]^k78);
    s117 = np.copy(l156^s126^s121*s130^s132*IR[64]^k78);s_117 = np.copy(l_156^s_126^s_121*s_130^s_132*IR[64]^k78);
    s116 = np.copy(l155^s125^s120*s129^s131*IR[63]^k76);s_116 = np.copy(l_155^s_125^s_120*s_129^s_131*IR[63]^k76);
    s115 = np.copy(l154^s124^s119*s128^s130*IR[63]^k76);s_115 = np.copy(l_154^s_124^s_119*s_128^s_130*IR[63]^k76);
    s114 = np.copy(l153^s123^s118*s127^s129*IR[63]^k76);s_114 = np.copy(l_153^s_123^s_118*s_127^s_129*IR[63]^k76);
 
    l134 = np.copy(s159^l147^l139*l151^l158*l163^k89);l_134 = np.copy(s_159^l_147^l_139*l_151^l_158*l_163^k89);
    l133 = np.copy(s158^l146^l138*l150^l157*l162^k89);l_133 = np.copy(s_158^l_146^l_138*l_150^l_157*l_162^k89);
    l132 = np.copy(s157^l145^l137*l149^l156*l161^k89);l_132 = np.copy(s_157^l_145^l_137*l_149^l_156*l_161^k89);
    l131 = np.copy(s156^l144^l136*l148^l155*l160^k87);l_131 = np.copy(s_156^l_144^l_136*l_148^l_155*l_160^k87);
    l130 = np.copy(s155^l143^l135*l147^l154*l159^k87);l_130 = np.copy(s_155^l_143^l_135*l_147^l_154*l_159^k87);
    l129 = np.copy(s154^l142^l134*l146^l153*l158^k87);l_129 = np.copy(s_154^l_142^l_134*l_146^l_153*l_158^k87);
    l128 = np.copy(s153^l141^l133*l145^l152*l157^k85);l_128 = np.copy(s_153^l_141^l_133*l_145^l_152*l_157^k85);
    l127 = np.copy(s152^l140^l132*l144^l151*l156^k85);l_127 = np.copy(s_152^l_140^l_132*l_144^l_151*l_156^k85);
    l126 = np.copy(s151^l139^l131*l143^l150*l155^k85);l_126 = np.copy(s_151^l_139^l_131*l_143^l_150*l_155^k85);
    l125 = np.copy(s150^l138^l130*l142^l149*l154^k83);l_125 = np.copy(s_150^l_138^l_130*l_142^l_149*l_154^k83);
    l124 = np.copy(s149^l137^l129*l141^l148*l153^k83);l_124 = np.copy(s_149^l_137^l_129*l_141^l_148*l_153^k83);
    l123 = np.copy(s148^l136^l128*l140^l147*l152^k83);l_123 = np.copy(s_148^l_136^l_128*l_140^l_147*l_152^k83);
    l122 = np.copy(s147^l135^l127*l139^l146*l151^k81);l_122 = np.copy(s_147^l_135^l_127*l_139^l_146*l_151^k81);
    l121 = np.copy(s146^l134^l126*l138^l145*l150^k81);l_121 = np.copy(s_146^l_134^l_126*l_138^l_145*l_150^k81);
    l120 = np.copy(s145^l133^l125*l137^l144*l149^k81);l_120 = np.copy(s_145^l_133^l_125*l_137^l_144*l_149^k81);
    l119 = np.copy(s144^l132^l124*l136^l143*l148^k79);l_119 = np.copy(s_144^l_132^l_124*l_136^l_143*l_148^k79);
    l118 = np.copy(s143^l131^l123*l135^l142*l147^k79);l_118 = np.copy(s_143^l_131^l_123*l_135^l_142*l_147^k79);
    l117 = np.copy(s142^l130^l122*l134^l141*l146^k79);l_117 = np.copy(s_142^l_130^l_122*l_134^l_141*l_146^k79);
    l116 = np.copy(s141^l129^l121*l133^l140*l145^k77);l_116 = np.copy(s_141^l_129^l_121*l_133^l_140*l_145^k77);
    l115 = np.copy(s140^l128^l120*l132^l139*l144^k77);l_115 = np.copy(s_140^l_128^l_120*l_132^l_139*l_144^k77);
    l114 = np.copy(s139^l127^l119*l131^l138*l143^k77);l_114 = np.copy(s_139^l_127^l_119*l_131^l_138*l_143^k77);
 

    s114=s114<<63;s115=s115<<62;s116=s116<<61;s117=s117<<60;s118=s118<<59;s119=s119<<58;s120=s120<<57;s121=s121<<56;
    s122=s122<<55;s123=s123<<54;s124=s124<<53;s125=s125<<52;s126=s126<<51;s127=s127<<50;s128=s128<<49;s129=s129<<48;
    s130=s130<<47;s131=s131<<46;s132=s132<<45;s133=s133<<44;s134=s134<<43;s135=s135<<42;s136=s136<<41;s137=s137<<40;
    s138=s138<<39;l114=l114<<38;l115=l115<<37;l116=l116<<36;l117=l117<<35;l118=l118<<34;l119=l119<<33;l120=l120<<32;
    l121=l121<<31;l122=l122<<30;l123=l123<<29;l124=l124<<28;l125=l125<<27;l126=l126<<26;l127=l127<<25;l128=l128<<24;
    l129=l129<<23;l130=l130<<22;l131=l131<<21;l132=l132<<20;l133=l133<<19;l134=l134<<18;l135=l135<<17;l136=l136<<16;
    l137=l137<<15;l138=l138<<14;l139=l139<<13;l140=l140<<12;l141=l141<<11;l142=l142<<10;l143=l143<<9;l144=l144<<8;
    l145=l145<<7;l146=l146<<6;l147=l147<<5;l148=l148<<4;l149=l149<<3;l150=l150<<2;l151=l151<<1;l152=l152;
    
    s_114=s_114<<63;s_115=s_115<<62;s_116=s_116<<61;s_117=s_117<<60;s_118=s_118<<59;s_119=s_119<<58;s_120=s_120<<57;s_121=s_121<<56;
    s_122=s_122<<55;s_123=s_123<<54;s_124=s_124<<53;s_125=s_125<<52;s_126=s_126<<51;s_127=s_127<<50;s_128=s_128<<49;s_129=s_129<<48;
    s_130=s_130<<47;s_131=s_131<<46;s_132=s_132<<45;s_133=s_133<<44;s_134=s_134<<43;s_135=s_135<<42;s_136=s_136<<41;s_137=s_137<<40;
    s_138=s_138<<39;l_114=l_114<<38;l_115=l_115<<37;l_116=l_116<<36;l_117=l_117<<35;l_118=l_118<<34;l_119=l_119<<33;l_120=l_120<<32;
    l_121=l_121<<31;l_122=l_122<<30;l_123=l_123<<29;l_124=l_124<<28;l_125=l_125<<27;l_126=l_126<<26;l_127=l_127<<25;l_128=l_128<<24;
    l_129=l_129<<23;l_130=l_130<<22;l_131=l_131<<21;l_132=l_132<<20;l_133=l_133<<19;l_134=l_134<<18;l_135=l_135<<17;l_136=l_136<<16;
    l_137=l_137<<15;l_138=l_138<<14;l_139=l_139<<13;l_140=l_140<<12;l_141=l_141<<11;l_142=l_142<<10;l_143=l_143<<9;l_144=l_144<<8;
    l_145=l_145<<7;l_146=l_146<<6;l_147=l_147<<5;l_148=l_148<<4;l_149=l_149<<3;l_150=l_150<<2;l_151=l_151<<1;l_152=l_152;
    
    ctdata0 = 0x0^(s114^s115^s116^s117^s118^s119^s120^s121^s122^s123^s124^s125^s126^s127^s128^s129^s130^s131^s132^s133^s134^s135^s136^s137^s138^l114^l115^l116^l117^l118^l119^l120^l121^l122^l123^l124^l125^l126^l127^l128^l129^l130
                   ^l131^l132^l133^l134^l135^l136^l137^l138^l139^l140^l141^l142^l143^l144^l145^l146^l147^l148^l149^l150^l151^l152);
    ctdata1 = 0x0^(s_114^s_115^s_116^s_117^s_118^s_119^s_120^s_121^s_122^s_123^s_124^s_125^s_126^s_127^s_128^s_129^s_130^s_131^s_132^s_133^s_134^s_135^s_136^s_137^s_138^l_114^l_115^l_116^l_117^l_118^l_119^l_120^l_121^l_122^l_123^l_124^l_125^l_126^l_127^l_128^l_129^l_130
                   ^l_131^l_132^l_133^l_134^l_135^l_136^l_137^l_138^l_139^l_140^l_141^l_142^l_143^l_144^l_145^l_146^l_147^l_148^l_149^l_150^l_151^l_152);
    return (ctdata0,ctdata1)

def dec_rounds2(ctdata0,ctdata1,ck2):
    k=np.copy(ck2);
    k74=np.copy(k&0x8000)>>15;  
    k75=np.copy(k&0x4000)>>14;
    k76=np.copy(k&0x2000)>>13;
    k77=np.copy(k&0x1000)>>12;
    k78=np.copy(k&0x800)>>11;
    k79=np.copy(k&0x400)>>10;
    k80=np.copy(k&0x200)>>9;
    k81=np.copy(k&0x100)>>8;
    k82=np.copy(k&0x80)>>7;
    k83=np.copy(k&0x40)>>6;
    k84=np.copy(k&0x20)>>5;
    k85=np.copy(k&0x10)>>4;
    k86=np.copy(k&0x8)>>3;
    k87=np.copy(k&0x4)>>2;
    k88=np.copy(k&0x2)>>1;
    k89=np.copy(k&0x1);

    s135 = np.copy(ctdata0)>>63;
    s135 = np.absolute(s135)
    s136 = np.copy(ctdata0&0x4000000000000000)>>62;s137 = np.copy(ctdata0&0x2000000000000000)>>61;s138 = np.copy(ctdata0&0x1000000000000000)>>60;
    s139 = np.copy(ctdata0&0x0800000000000000)>>59;s140 = np.copy(ctdata0&0x0400000000000000)>>58;s141 = np.copy(ctdata0&0x0200000000000000)>>57;s142 = np.copy(ctdata0&0x0100000000000000)>>56;
    s143 = np.copy(ctdata0&0x0080000000000000)>>55;s144 = np.copy(ctdata0&0x0040000000000000)>>54;s145 = np.copy(ctdata0&0x0020000000000000)>>53;s146 = np.copy(ctdata0&0x0010000000000000)>>52;
    s147 = np.copy(ctdata0&0x0008000000000000)>>51;s148 = np.copy(ctdata0&0x0004000000000000)>>50;s149 = np.copy(ctdata0&0x0002000000000000)>>49;s150 = np.copy(ctdata0&0x0001000000000000)>>48;
    s151 = np.copy(ctdata0&0x0000800000000000)>>47;s152 = np.copy(ctdata0&0x0000400000000000)>>46;s153 = np.copy(ctdata0&0x0000200000000000)>>45;s154 = np.copy(ctdata0&0x0000100000000000)>>44;
    s155 = np.copy(ctdata0&0x0000080000000000)>>43;s156 = np.copy(ctdata0&0x0000040000000000)>>42;s157 = np.copy(ctdata0&0x0000020000000000)>>41;s158 = np.copy(ctdata0&0x0000010000000000)>>40;
    s159 = np.copy(ctdata0&0x0000008000000000)>>39;l135 = np.copy(ctdata0&0x0000004000000000)>>38;l136 = np.copy(ctdata0&0x0000002000000000)>>37;l137 = np.copy(ctdata0&0x0000001000000000)>>36;
    l138 = np.copy(ctdata0&0x0000000800000000)>>35;l139 = np.copy(ctdata0&0x0000000400000000)>>34;l140 = np.copy(ctdata0&0x0000000200000000)>>33;l141 = np.copy(ctdata0&0x0000000100000000)>>32;
    l142 = np.copy(ctdata0&0x0000000080000000)>>31;l143 = np.copy(ctdata0&0x0000000040000000)>>30;l144 = np.copy(ctdata0&0x0000000020000000)>>29;l145 = np.copy(ctdata0&0x0000000010000000)>>28;
    l146 = np.copy(ctdata0&0x0000000008000000)>>27;l147 = np.copy(ctdata0&0x0000000004000000)>>26;l148 = np.copy(ctdata0&0x0000000002000000)>>25;l149 = np.copy(ctdata0&0x0000000001000000)>>24;
    l150 = np.copy(ctdata0&0x0000000000800000)>>23;l151 = np.copy(ctdata0&0x0000000000400000)>>22;l152 = np.copy(ctdata0&0x0000000000200000)>>21;l153 = np.copy(ctdata0&0x0000000000100000)>>20;
    l154 = np.copy(ctdata0&0x0000000000080000)>>19;l155 = np.copy(ctdata0&0x0000000000040000)>>18;l156 = np.copy(ctdata0&0x0000000000020000)>>17;l157 = np.copy(ctdata0&0x0000000000010000)>>16;
    l158 = np.copy(ctdata0&0x0000000000008000)>>15;l159 = np.copy(ctdata0&0x0000000000004000)>>14;l160 = np.copy(ctdata0&0x0000000000002000)>>13;l161 = np.copy(ctdata0&0x0000000000001000)>>12;
    l162 = np.copy(ctdata0&0x0000000000000800)>>11;l163 = np.copy(ctdata0&0x0000000000000400)>>10;l164 = np.copy(ctdata0&0x0000000000000200)>>9;l165 = np.copy(ctdata0&0x0000000000000100)>>8;
    l166 = np.copy(ctdata0&0x0000000000000080)>>7;l167 = np.copy(ctdata0&0x0000000000000040)>>6;l168 = np.copy(ctdata0&0x0000000000000020)>>5;l169 = np.copy(ctdata0&0x0000000000000010)>>4;
    l170 = np.copy(ctdata0&0x0000000000000008)>>3;l171 = np.copy(ctdata0&0x0000000000000004)>>2;l172 = np.copy(ctdata0&0x0000000000000002)>>1;l173 = np.copy(ctdata0&0x0000000000000001);

    s_135 = np.copy(ctdata1)>>63;
    s_135 = np.absolute(s_135)
    s_136 = np.copy(ctdata1&0x4000000000000000)>>62;s_137 = np.copy(ctdata1&0x2000000000000000)>>61;s_138 = np.copy(ctdata1&0x1000000000000000)>>60;
    s_139 = np.copy(ctdata1&0x0800000000000000)>>59;s_140 = np.copy(ctdata1&0x0400000000000000)>>58;s_141 = np.copy(ctdata1&0x0200000000000000)>>57;s_142 = np.copy(ctdata1&0x0100000000000000)>>56;
    s_143 = np.copy(ctdata1&0x0080000000000000)>>55;s_144 = np.copy(ctdata1&0x0040000000000000)>>54;s_145 = np.copy(ctdata1&0x0020000000000000)>>53;s_146 = np.copy(ctdata1&0x0010000000000000)>>52;
    s_147 = np.copy(ctdata1&0x0008000000000000)>>51;s_148 = np.copy(ctdata1&0x0004000000000000)>>50;s_149 = np.copy(ctdata1&0x0002000000000000)>>49;s_150 = np.copy(ctdata1&0x0001000000000000)>>48;
    s_151 = np.copy(ctdata1&0x0000800000000000)>>47;s_152 = np.copy(ctdata1&0x0000400000000000)>>46;s_153 = np.copy(ctdata1&0x0000200000000000)>>45;s_154 = np.copy(ctdata1&0x0000100000000000)>>44;
    s_155 = np.copy(ctdata1&0x0000080000000000)>>43;s_156 = np.copy(ctdata1&0x0000040000000000)>>42;s_157 = np.copy(ctdata1&0x0000020000000000)>>41;s_158 = np.copy(ctdata1&0x0000010000000000)>>40;
    s_159 = np.copy(ctdata1&0x0000008000000000)>>39;l_135 = np.copy(ctdata1&0x0000004000000000)>>38;l_136 = np.copy(ctdata1&0x0000002000000000)>>37;l_137 = np.copy(ctdata1&0x0000001000000000)>>36;
    l_138 = np.copy(ctdata1&0x0000000800000000)>>35;l_139 = np.copy(ctdata1&0x0000000400000000)>>34;l_140 = np.copy(ctdata1&0x0000000200000000)>>33;l_141 = np.copy(ctdata1&0x0000000100000000)>>32;
    l_142 = np.copy(ctdata1&0x0000000080000000)>>31;l_143 = np.copy(ctdata1&0x0000000040000000)>>30;l_144 = np.copy(ctdata1&0x0000000020000000)>>29;l_145 = np.copy(ctdata1&0x0000000010000000)>>28;
    l_146 = np.copy(ctdata1&0x0000000008000000)>>27;l_147 = np.copy(ctdata1&0x0000000004000000)>>26;l_148 = np.copy(ctdata1&0x0000000002000000)>>25;l_149 = np.copy(ctdata1&0x0000000001000000)>>24;
    l_150 = np.copy(ctdata1&0x0000000000800000)>>23;l_151 = np.copy(ctdata1&0x0000000000400000)>>22;l_152 = np.copy(ctdata1&0x0000000000200000)>>21;l_153 = np.copy(ctdata1&0x0000000000100000)>>20;
    l_154 = np.copy(ctdata1&0x0000000000080000)>>19;l_155 = np.copy(ctdata1&0x0000000000040000)>>18;l_156 = np.copy(ctdata1&0x0000000000020000)>>17;l_157 = np.copy(ctdata1&0x0000000000010000)>>16;
    l_158 = np.copy(ctdata1&0x0000000000008000)>>15;l_159 = np.copy(ctdata1&0x0000000000004000)>>14;l_160 = np.copy(ctdata1&0x0000000000002000)>>13;l_161 = np.copy(ctdata1&0x0000000000001000)>>12;
    l_162 = np.copy(ctdata1&0x0000000000000800)>>11;l_163 = np.copy(ctdata1&0x0000000000000400)>>10;l_164 = np.copy(ctdata1&0x0000000000000200)>>9;l_165 = np.copy(ctdata1&0x0000000000000100)>>8;
    l_166 = np.copy(ctdata1&0x0000000000000080)>>7;l_167 = np.copy(ctdata1&0x0000000000000040)>>6;l_168 = np.copy(ctdata1&0x0000000000000020)>>5;l_169 = np.copy(ctdata1&0x0000000000000010)>>4;
    l_170 = np.copy(ctdata1&0x0000000000000008)>>3;l_171 = np.copy(ctdata1&0x0000000000000004)>>2;l_172 = np.copy(ctdata1&0x0000000000000002)>>1;l_173 = np.copy(ctdata1&0x0000000000000001);
    

    s134 = np.copy(l173^s143^s138*s147^s149*IR[62]^k88);s_134 = np.copy(l_173^s_143^s_138*s_147^s_149*IR[62]^k88);
    s133 = np.copy(l172^s142^s137*s146^s148*IR[62]^k88);s_133 = np.copy(l_172^s_142^s_137*s_146^s_148*IR[62]^k88);
    s132 = np.copy(l171^s141^s136*s145^s147*IR[62]^k88);s_132 = np.copy(l_171^s_141^s_136*s_145^s_147*IR[62]^k88);
    s131 = np.copy(l170^s140^s135*s144^s146*IR[61]^k86);s_131 = np.copy(l_170^s_140^s_135*s_144^s_146*IR[61]^k86);
    s130 = np.copy(l169^s139^s134*s143^s145*IR[61]^k86);s_130 = np.copy(l_169^s_139^s_134*s_143^s_145*IR[61]^k86);
    s129 = np.copy(l168^s138^s133*s142^s144*IR[61]^k86);s_129 = np.copy(l_168^s_138^s_133*s_142^s_144*IR[61]^k86);
    s128 = np.copy(l167^s137^s132*s141^s143*IR[60]^k84);s_128 = np.copy(l_167^s_137^s_132*s_141^s_143*IR[60]^k84);
    s127 = np.copy(l166^s136^s131*s140^s142*IR[60]^k84);s_127 = np.copy(l_166^s_136^s_131*s_140^s_142*IR[60]^k84);
    s126 = np.copy(l165^s135^s130*s139^s141*IR[60]^k84);s_126 = np.copy(l_165^s_135^s_130*s_139^s_141*IR[60]^k84);
    s125 = np.copy(l164^s134^s129*s138^s140*IR[59]^k82);s_125 = np.copy(l_164^s_134^s_129*s_138^s_140*IR[59]^k82);
    s124 = np.copy(l163^s133^s128*s137^s139*IR[59]^k82);s_124 = np.copy(l_163^s_133^s_128*s_137^s_139*IR[59]^k82);
    s123 = np.copy(l162^s132^s127*s136^s138*IR[59]^k82);s_123 = np.copy(l_162^s_132^s_127*s_136^s_138*IR[59]^k82);
    s122 = np.copy(l161^s131^s126*s135^s137*IR[58]^k80);s_122 = np.copy(l_161^s_131^s_126*s_135^s_137*IR[58]^k80);
    s121 = np.copy(l160^s130^s125*s134^s136*IR[58]^k80);s_121 = np.copy(l_160^s_130^s_125*s_134^s_136*IR[58]^k80);
    s120 = np.copy(l159^s129^s124*s133^s135*IR[58]^k80);s_120 = np.copy(l_159^s_129^s_124*s_133^s_135*IR[58]^k80);
    s119 = np.copy(l158^s128^s123*s132^s134*IR[57]^k78);s_119 = np.copy(l_158^s_128^s_123*s_132^s_134*IR[57]^k78);
    s118 = np.copy(l157^s127^s122*s131^s133*IR[57]^k78);s_118 = np.copy(l_157^s_127^s_122*s_131^s_133*IR[57]^k78);
    s117 = np.copy(l156^s126^s121*s130^s132*IR[57]^k78);s_117 = np.copy(l_156^s_126^s_121*s_130^s_132*IR[57]^k78);
    s116 = np.copy(l155^s125^s120*s129^s131*IR[56]^k76);s_116 = np.copy(l_155^s_125^s_120*s_129^s_131*IR[56]^k76);
    s115 = np.copy(l154^s124^s119*s128^s130*IR[56]^k76);s_115 = np.copy(l_154^s_124^s_119*s_128^s_130*IR[56]^k76);
    s114 = np.copy(l153^s123^s118*s127^s129*IR[56]^k76);s_114 = np.copy(l_153^s_123^s_118*s_127^s_129*IR[56]^k76);
    s113 = np.copy(l152^s122^s117*s126^s128*IR[55]^k74);s_113 = np.copy(l_152^s_122^s_117*s_126^s_128*IR[55]^k74);
    s112 = np.copy(l151^s121^s116*s125^s127*IR[55]^k74);s_112 = np.copy(l_151^s_121^s_116*s_125^s_127*IR[55]^k74);
    
    l134 = np.copy(s159^l147^l139*l151^l158*l163^k89);l_134 = np.copy(s_159^l_147^l_139*l_151^l_158*l_163^k89);
    l133 = np.copy(s158^l146^l138*l150^l157*l162^k89);l_133 = np.copy(s_158^l_146^l_138*l_150^l_157*l_162^k89);
    l132 = np.copy(s157^l145^l137*l149^l156*l161^k89);l_132 = np.copy(s_157^l_145^l_137*l_149^l_156*l_161^k89);
    l131 = np.copy(s156^l144^l136*l148^l155*l160^k87);l_131 = np.copy(s_156^l_144^l_136*l_148^l_155*l_160^k87);
    l130 = np.copy(s155^l143^l135*l147^l154*l159^k87);l_130 = np.copy(s_155^l_143^l_135*l_147^l_154*l_159^k87);
    l129 = np.copy(s154^l142^l134*l146^l153*l158^k87);l_129 = np.copy(s_154^l_142^l_134*l_146^l_153*l_158^k87);
    l128 = np.copy(s153^l141^l133*l145^l152*l157^k85);l_128 = np.copy(s_153^l_141^l_133*l_145^l_152*l_157^k85);
    l127 = np.copy(s152^l140^l132*l144^l151*l156^k85);l_127 = np.copy(s_152^l_140^l_132*l_144^l_151*l_156^k85);
    l126 = np.copy(s151^l139^l131*l143^l150*l155^k85);l_126 = np.copy(s_151^l_139^l_131*l_143^l_150*l_155^k85);
    l125 = np.copy(s150^l138^l130*l142^l149*l154^k83);l_125 = np.copy(s_150^l_138^l_130*l_142^l_149*l_154^k83);
    l124 = np.copy(s149^l137^l129*l141^l148*l153^k83);l_124 = np.copy(s_149^l_137^l_129*l_141^l_148*l_153^k83);
    l123 = np.copy(s148^l136^l128*l140^l147*l152^k83);l_123 = np.copy(s_148^l_136^l_128*l_140^l_147*l_152^k83);
    l122 = np.copy(s147^l135^l127*l139^l146*l151^k81);l_122 = np.copy(s_147^l_135^l_127*l_139^l_146*l_151^k81);
    l121 = np.copy(s146^l134^l126*l138^l145*l150^k81);l_121 = np.copy(s_146^l_134^l_126*l_138^l_145*l_150^k81);
    l120 = np.copy(s145^l133^l125*l137^l144*l149^k81);l_120 = np.copy(s_145^l_133^l_125*l_137^l_144*l_149^k81);
    l119 = np.copy(s144^l132^l124*l136^l143*l148^k79);l_119 = np.copy(s_144^l_132^l_124*l_136^l_143*l_148^k79);
    l118 = np.copy(s143^l131^l123*l135^l142*l147^k79);l_118 = np.copy(s_143^l_131^l_123*l_135^l_142*l_147^k79);
    l117 = np.copy(s142^l130^l122*l134^l141*l146^k79);l_117 = np.copy(s_142^l_130^l_122*l_134^l_141*l_146^k79);
    l116 = np.copy(s141^l129^l121*l133^l140*l145^k77);l_116 = np.copy(s_141^l_129^l_121*l_133^l_140*l_145^k77);
    l115 = np.copy(s140^l128^l120*l132^l139*l144^k77);l_115 = np.copy(s_140^l_128^l_120*l_132^l_139*l_144^k77);
    l114 = np.copy(s139^l127^l119*l131^l138*l143^k77);l_114 = np.copy(s_139^l_127^l_119*l_131^l_138*l_143^k77);
    l113 = np.copy(s138^l126^l118*l130^l137*l142^k75);l_113 = np.copy(s_138^l_126^l_118*l_130^l_137*l_142^k75);
    

    
    c39 = np.copy(s132^s_132);
    c40 = np.copy(s131^s_131);
    c41 = np.copy(s130^s_130);
    c42 = np.copy(s129^s_129);
    c43 = np.copy(s128^s_128);
    c44 = np.copy(s127^s_127);
    c45 = np.copy(s126^s_126);
    c46 = np.copy(s125^s_125);
    c47 = np.copy(s124^s_124);
    c48 = np.copy(s123^s_123);
    c49 = np.copy(s122^s_122);
    c50 = np.copy(s121^s_121);
    c51 = np.copy(s120^s_120);
    c52 = np.copy(s119^s_119);
    c53 = np.copy(s118^s_118);
    c54 = np.copy(s117^s_117);
    c55 = np.copy(s116^s_116);
    c56 = np.copy(s115^s_115);
    c57 = np.copy(s114^s_114);
    c58 = np.copy(s113^s_113);
    c59 = np.copy(s112^s_112);
    c60 = np.copy((l150^s120^s115*s124^s126*IR[55])^(l_150^s_120^s_115*s_124^s_126*IR[55]));
    c61 = np.copy((l149^s119^s114*s123^s125*IR[54])^(l_149^s_119^s_114*s_123^s_125*IR[54]));
    c62 = np.copy((l148^s118^s113*s122^s124*IR[54])^(l_148^s_118^s_113*s_122^s_124*IR[54]));
    c63 = np.copy((l147^s117^s112*s121^s123*IR[54])^(l_147^s_117^s_112*s_121^s_123*IR[54]));

    c0 = np.copy(l146^l_146);c1 = np.copy(l145^l_145);c2 = np.copy(l144^l_144);c3 = np.copy(l143^l_143);
    c4 = np.copy(l142^l_142);c5 = np.copy(l141^l_141);c6 = np.copy(l140^l_140);c7 = np.copy(l139^l_139);
    c8 = np.copy(l138^l_138);c9 = np.copy(l137^l_137);c10 = np.copy(l136^l_136);c11 = np.copy(l135^l_135);
    c12 = np.copy(l134^l_134);c13 = np.copy(l133^l_133);c14 = np.copy(l132^l_132);c15 = np.copy(l131^l_131);
    c16 = np.copy(l130^l_130);c17 = np.copy(l129^l_129);c18 = np.copy(l128^l_128);c19 = np.copy(l127^l_127);
    c20 = np.copy(l126^l_126);c21 = np.copy(l125^l_125);
    c22 = np.copy(l124^l_124);
    c23 = np.copy(l123^l_123);
    c24 = np.copy(l122^l_122);
    c25 = np.copy(l121^l_121);
    c26 = np.copy(l120^l_120);
    c27 = np.copy(l119^l_119);
    c28 = np.copy(l118^l_118);
    c29 = np.copy(l117^l_117);
    c30 = np.copy(l116^l_116);
    c31 = np.copy(l115^l_115);
    c32 = np.copy(l114^l_114);
    c33 = np.copy(l113^l_113);
    c34 = np.copy((s137^l125^l117*l129^l136*l141)^(s_137^l_125^l_117*l_129^l_136*l_141));
    c35 = np.copy((s136^l124^l116*l128^l135*l140)^(s_136^l_124^l_116*l_128^l_135*l_140));
    c36 = np.copy((s135^l123^l115*l127^l134*l139)^(s_135^l_123^l_115*l_127^l_134*l_139));
    c37 = np.copy((s134^l122^l114*l126^l133*l138)^(s_134^l_122^l_114*l_126^l_133*l_138));
    c38 = np.copy((s133^l121^l113*l125^l132*l137)^(s_133^l_121^l_113*l_125^l_132*l_137));
    

    c63=c63<<63;c62=c62<<62;c61=c61<<61;c60=c60<<60;c59=c59<<59;c58=c58<<58;c57=c57<<57;c56=c56<<56;
    c55=c55<<55;c54=c54<<54;c53=c53<<53;c52=c52<<52;c51=c51<<51;c50=c50<<50;c49=c49<<49;c48=c48<<48;
    c47=c47<<47;c46=c46<<46;c45=c45<<45;c44=c44<<44;c43=c43<<43;c42=c42<<42;c41=c41<<41;c40=c40<<40;
    c39=c39<<39;c38=c38<<38;c37=c37<<37;c36=c36<<36;c35=c35<<35;c34=c34<<34;c33=c33<<33;c32=c32<<32;
    c31=c31<<31;c30=c30<<30;c29=c29<<29;c28=c28<<28;c27=c27<<27;c26=c26<<26;c25=c25<<25;c24=c24<<24;
    c23=c23<<23;c22=c22<<22;c21=c21<<21;c20=c20<<20;c19=c19<<19;c18=c18<<18;c17=c17<<17;c16=c16<<16;
    c15=c15<<15;c14=c14<<14;c13=c13<<13;c12=c12<<12;c11=c11<<11;c10=c10<<10;c9=c9<<9;c8=c8<<8;
    c7=c7<<7;c6=c6<<6;c5=c5<<5;c4=c4<<4;c3=c3<<3;c2=c2<<2;c1=c1<<1;c0=c0;
    ctdata=0x0^(c63^c62^c61^c60^c59^c58^c57^c56^c55^c54^c53^c52^c51^c50^c49^c48^c47^c46^c45^c44^c43^c42^c41^c40^c39^c38^c37^c36^c35^c34^c33^c32^c31^c30^c29^c28^c27^c26^c25^c24^c23^c22^c21^c20^c19^c18^c17^c16^c15^c14^c13^c12^c11^c10^c9^c8^c7^c6^c5^c4^c3^c2^c1^c0); 
     
    return ctdata



