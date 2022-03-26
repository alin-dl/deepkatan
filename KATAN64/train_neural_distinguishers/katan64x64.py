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

# Training data for conditional neural distinguisher 
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
        plain0 = np.copy(plain0&0xFF6CBDFF7FBAFD5D^0x80000000000000)
        # Generate 32 plaintext registers
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

#make_train_data(2, 79, 0xc4200801)
#make_val_data(10**4, 40, (0xc420,0x0801))

