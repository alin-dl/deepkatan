# -*- coding: utf-8 -*-
"""
Created on Sun Nov 14 20:03:29 2021

@author: deeplearning
"""

# -*- coding: utf-8 -*-
"""
Created on Tue Oct 26 20:26:54 2021

@author: deeplearning
"""

from gurobipy import *  
import numpy  
import math  
import time  
  
time_start=time.time()
#Record start time
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
r=26#Take the r-round differential path as an example  

# Create a new model

m = Model("KATAN32")#Build the KATAN32 MILP model 
# Create variables  
x = m.addVars(32, vtype=gurobipy.GRB.BINARY, name="x")
c = m.addVars(r,2, vtype=gurobipy.GRB.BINARY, name="c")
s = m.addVars(267,vtype=gurobipy.GRB.BINARY,name="s")
l = m.addVars(273, vtype=gurobipy.GRB.BINARY, name="l") 
  
m.update() # update variable environment

# Set objective  
#sum1=0
#for i in range(r):
#    for j in range(3):
#        sum1 += c[i][j]
#        m.setObjective(sum1, GRB.MINIMIZE) 
m.setObjective(quicksum(c[i,j] for i in range(r) for j in range(2)), GRB.MINIMIZE)
# Add constraint

m.addConstr(s[r]==0);m.addConstr(s[r+1]==0);m.addConstr(s[r+2]==0);m.addConstr(s[r+3]==0);
m.addConstr(s[r+4]==0);m.addConstr(s[r+5]==0);m.addConstr(s[r+6]==0);m.addConstr(s[r+7]==0);
m.addConstr(s[r+8]==0);m.addConstr(s[r+9]==0);m.addConstr(s[r+10]==0);m.addConstr(s[r+11]==0);
m.addConstr(s[r+12]==0);m.addConstr(l[r]==0);m.addConstr(l[r+1]==0);m.addConstr(l[r+2]==0);
m.addConstr(l[r+3]==0);m.addConstr(l[r+4]==0);m.addConstr(l[r+5]==1);m.addConstr(l[r+6]==0);
m.addConstr(l[r+7]==0);m.addConstr(l[r+8]==0);m.addConstr(l[r+9]==0);m.addConstr(l[r+10]==0);
m.addConstr(l[r+11]==0);m.addConstr(l[r+12]==0);m.addConstr(l[r+13]==0);m.addConstr(l[r+14]==0);
m.addConstr(l[r+15]==0);m.addConstr(l[r+16]==0);m.addConstr(l[r+17]==0);m.addConstr(l[r+18]==0);

#n = r

m#.addConstr(quicksum((s[n+i]) for i in range(13))+quicksum((l[n+j] for j in range(19)))<=1)

for j in range(13):
    m.addConstr(s[j]==x[31-j])
for k in range(19):
    m.addConstr(l[k]==x[18-k])
flag1=[0,11,6,8,10,15,13]  
flag2=[0,5,4,7,9,19]
flag3=[0,5,4,7,19]
#print(type(flag1[6]))
for i in range(r):#calculation for r-round 
    m.addConstr(-s[i+flag1[6]]-c[i,0]+1>=0)
    m.addConstr(-l[i+flag1[2]]+c[i,0]>=0)
    m.addConstr(-l[i]-l[i+flag1[1]]-s[i+flag1[6]]+2>=0)
    m.addConstr(-l[i+flag1[3]]+c[i,0]>=0)
    m.addConstr(-l[i+flag1[4]]+c[i,0]>=0)
    m.addConstr(-l[i+flag1[5]]+c[i,0]>=0)
    m.addConstr(l[i]+l[i+flag1[1]]-s[i+flag1[6]]>=0)
    m.addConstr(-l[i]+l[i+flag1[1]]+s[i+flag1[6]]+c[i,0]>=0)
    m.addConstr(l[i]-l[i+flag1[1]]+s[i+flag1[6]]+c[i,0]>=0)
    m.addConstr(l[i+flag1[2]]+l[i+flag1[3]]+l[i+flag1[4]]+l[i+flag1[5]]-c[i,0]>=0)
    if IR[r]==1:
        m.addConstr(-l[i+flag2[5]]-c[i,1]+1>=0)
        m.addConstr(-s[i+flag2[3]]+c[i,1]>=0)
        m.addConstr(-s[i+flag2[2]]+c[i,1]>=0)
        m.addConstr(s[i+flag2[2]]+s[i+flag2[3]]-c[i,1]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]>=0)
        m.addConstr(-s[i]-s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[i,1]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[i,1]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[i,1]>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[i,1]>=0)
    else:
        m.addConstr(-l[i+flag3[4]]-c[i,1]+1>=0)
        m.addConstr(-s[i+flag3[2]]+c[i,1]>=0)
        m.addConstr(-s[i+flag3[3]]+c[i,1]>=0)
        m.addConstr(s[i+flag3[2]]+s[i+7]-c[i,1]>=0)
        m.addConstr(s[i]-s[i+flag3[1]]+l[i+flag3[4]]+c[i,1]>=0)
        m.addConstr(-s[i]+s[i+flag3[1]]+l[i+flag3[4]]+c[i,1]>=0)
        m.addConstr(s[i]+s[i+flag3[1]]-l[i+flag3[4]]>=0)
        m.addConstr(-s[i]-s[i+flag3[1]]-l[i+flag3[4]]+2>=0)
m.addConstr(quicksum(x[j] for j in range(32))>=1)
'''
for i in range(32):
    m.addConstr(x[i] >= 0)
'''    
m.Params.LogToConsole=True # Show the solution process 
m.optimize() 

v = m.getVars()
for i in range(32+500):
    print('%s %g'%(v[i].varName,v[i].x))

cipher = list(range(32))
for i in range(13):
    cipher[i]=int(s[r+i].x)
    print(int(s[r+i].x))
for j in range(19):
    cipher[13+j]=int(l[r+j].x)
    print(int(l[r+j].x))

# the value of the output difference
MASK_VAL = 2 ** 32 - 1;

def rol(x,k):
    return(((x << k) & MASK_VAL) | (x >> (32 - k)));

b=0

for i in range(32):
    b=b^rol(cipher[31-i],i)
print(hex(b))   


#for i in range(32+10*r):
#    print('%s %g'%(v[i].varName,v[i].x))
#for v in m.getVars():  
#    print('%s %g' % (v.varName, v.x))

print('Obj: %g' % m.objVal)  

time_end=time.time()
#Record end time
print('time cost',time_end-time_start,'s')  
