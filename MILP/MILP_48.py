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
  
time_start=time.time()#Record start time 
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
r=25#Take the r-round differential path as an example  

# Create a new model

m = Model("KATAN48")#Build the KATAN48 MILP model   
# Create variables  
x = m.addVars(48, vtype=gurobipy.GRB.BINARY, name="x")
c = m.addVars(r,4, vtype=gurobipy.GRB.BINARY, name="c")
s = m.addVars(525,vtype=gurobipy.GRB.BINARY,name="s")
l = m.addVars(537, vtype=gurobipy.GRB.BINARY, name="l")
  
m.update()  # update variable environment  

# Set objective  
#sum1=0
#for i in range(r):
#    for j in range(3):
#        sum1 += c[i][j]
#        m.setObjective(sum1, GRB.MINIMIZE) 
m.setObjective(quicksum(c[i,j] for i in range(r) for j in range(4)), GRB.MINIMIZE)
# Add constraint

n = 2*r
m.addConstr(s[n]==0);m.addConstr(s[n+1]==0);m.addConstr(s[n+2]==0);m.addConstr(s[n+3]==0);
m.addConstr(s[n+4]==0);m.addConstr(s[n+5]==1);m.addConstr(s[n+6]==0);m.addConstr(s[n+7]==0);
m.addConstr(s[n+8]==0);m.addConstr(s[n+9]==0);m.addConstr(s[n+10]==0);m.addConstr(s[n+11]==0);
m.addConstr(s[n+12]==0);m.addConstr(s[n+13]==0);m.addConstr(s[n+14]==0);m.addConstr(s[n+15]==0);
m.addConstr(s[n+16]==0);m.addConstr(s[n+17]==0);m.addConstr(s[n+18]==0);
m.addConstr(l[n]==0);m.addConstr(l[n+1]==0);m.addConstr(l[n+2]==0);m.addConstr(l[n+3]==0);
m.addConstr(l[n+4]==0);m.addConstr(l[n+5]==0);m.addConstr(l[n+6]==0);m.addConstr(l[n+7]==0);
m.addConstr(l[n+8]==0);m.addConstr(l[n+9]==0);m.addConstr(l[n+10]==0);m.addConstr(l[n+11]==0);
m.addConstr(l[n+12]==0);m.addConstr(l[n+13]==0);m.addConstr(l[n+14]==0);m.addConstr(l[n+15]==0);
m.addConstr(l[n+16]==0);m.addConstr(l[n+17]==0);m.addConstr(l[n+18]==0);m.addConstr(l[n+19]==0);
m.addConstr(l[n+20]==0);m.addConstr(l[n+21]==0);m.addConstr(l[n+22]==0);m.addConstr(l[n+23]==0);
m.addConstr(l[n+24]==0);m.addConstr(l[n+25]==0);m.addConstr(l[n+26]==0);m.addConstr(l[n+27]==0);
m.addConstr(l[n+28]==0);


#n = 2*r

#m.addConstr(quicksum((s[n+i]) for i in range(19))+quicksum((l[n+j] for j in range(29)))<=1)

for j in range(19):
    m.addConstr(s[j]==x[47-j])
for k in range(29):
    m.addConstr(l[k]==x[28-k])
#KATAN32
'''
flag1=[0,11,6,8,10,15,13]  
flag2=[0,5,4,7,9,19]
flag3=[0,5,4,7,19]
'''
#KATAN48
flag1=[0,9,7,15,13,22,19]  
flag2=[0,6,3,11,12,29]
flag3=[0,6,3,11,29]
#print(type(flag1[6]))
i=0

for z in range(r):#calculation for r-round 
    m.addConstr(-s[i+flag1[6]]-c[z,0]+1>=0)
    m.addConstr(-l[i+flag1[2]]+c[z,0]>=0)
    m.addConstr(-l[i]-l[i+flag1[1]]-s[i+flag1[6]]+2>=0)
    m.addConstr(-l[i+flag1[3]]+c[z,0]>=0)
    m.addConstr(-l[i+flag1[4]]+c[z,0]>=0)
    m.addConstr(-l[i+flag1[5]]+c[z,0]>=0)
    m.addConstr(l[i]+l[i+flag1[1]]-s[i+flag1[6]]>=0)
    m.addConstr(-l[i]+l[i+flag1[1]]+s[i+flag1[6]]+c[z,0]>=0)
    m.addConstr(l[i]-l[i+flag1[1]]+s[i+flag1[6]]+c[z,0]>=0)
    m.addConstr(l[i+flag1[2]]+l[i+flag1[3]]+l[i+flag1[4]]+l[i+flag1[5]]-c[z,0]>=0)
    # a=1
    if IR[z]==1:
        m.addConstr(-l[i+flag2[5]]-c[z,1]+1>=0)
        m.addConstr(-s[i+flag2[3]]+c[z,1]>=0)
        m.addConstr(-s[i+flag2[2]]+c[z,1]>=0)
        m.addConstr(s[i+flag2[2]]+s[i+flag2[3]]-c[z,1]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]>=0)
        m.addConstr(-s[i]-s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,1]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,1]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,1]>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,1]>=0)
    # a=0
    if IR[z]==0:
        m.addConstr(-l[i+flag3[4]]-c[z,1]+1>=0)
        m.addConstr(-s[i+flag3[2]]+c[z,1]>=0)
        m.addConstr(-s[i+flag3[3]]+c[z,1]>=0)
        m.addConstr(s[i+flag3[2]]+s[i+7]-c[z,1]>=0)
        m.addConstr(s[i]-s[i+flag3[1]]+l[i+flag3[4]]+c[z,1]>=0)
        m.addConstr(-s[i]+s[i+flag3[1]]+l[i+flag3[4]]+c[z,1]>=0)
        m.addConstr(s[i]+s[i+flag3[1]]-l[i+flag3[4]]>=0)
        m.addConstr(-s[i]-s[i+flag3[1]]-l[i+flag3[4]]+2>=0)
    #KATAN48 second bit update
    i+=1
    m.addConstr(-s[i+flag1[6]]-c[z,2]+1>=0)
    m.addConstr(-l[i+flag1[2]]+c[z,2]>=0)
    m.addConstr(-l[i]-l[i+flag1[1]]-s[z+flag1[6]]+2>=0)
    m.addConstr(-l[i+flag1[3]]+c[z,2]>=0)
    m.addConstr(-l[i+flag1[4]]+c[z,2]>=0)
    m.addConstr(-l[i+flag1[5]]+c[z,2]>=0)
    m.addConstr(l[i]+l[i+flag1[1]]-s[i+flag1[6]]>=0)
    m.addConstr(-l[i]+l[i+flag1[1]]+s[i+flag1[6]]+c[z,2]>=0)
    m.addConstr(l[i]-l[i+flag1[1]]+s[i+flag1[6]]+c[z,2]>=0)
    m.addConstr(l[i+flag1[2]]+l[i+flag1[3]]+l[i+flag1[4]]+l[i+flag1[5]]-c[z,2]>=0)
    # a=1
    if IR[z]==1:
        m.addConstr(-l[i+flag2[5]]-c[z,3]+1>=0)
        m.addConstr(-s[i+flag2[3]]+c[z,3]>=0)
        m.addConstr(-s[i+flag2[2]]+c[z,3]>=0)
        m.addConstr(s[i+flag2[2]]+s[i+flag2[3]]-c[z,3]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]-s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]+s[i+flag2[4]]-l[i+flag2[5]]>=0)
        m.addConstr(-s[i]-s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,3]+2>=0)
        m.addConstr(s[i]+s[i+flag2[1]]-s[i+flag2[4]]+l[i+flag2[5]]+c[z,3]>=0)
        m.addConstr(s[i]-s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,3]>=0)
        m.addConstr(-s[i]+s[i+flag2[1]]+s[i+flag2[4]]+l[i+flag2[5]]+c[z,3]>=0)
    # a=0
    if IR[z]==0:
        m.addConstr(-l[i+flag3[4]]-c[z,3]+1>=0)
        m.addConstr(-s[i+flag3[2]]+c[z,3]>=0)
        m.addConstr(-s[i+flag3[3]]+c[z,3]>=0)
        m.addConstr(s[i+flag3[2]]+s[i+7]-c[z,3]>=0)
        m.addConstr(s[i]-s[i+flag3[1]]+l[i+flag3[4]]+c[z,3]>=0)
        m.addConstr(-s[i]+s[i+flag3[1]]+l[i+flag3[4]]+c[z,3]>=0)
        m.addConstr(s[i]+s[i+flag3[1]]-l[i+flag3[4]]>=0)
        m.addConstr(-s[i]-s[i+flag3[1]]-l[i+flag3[4]]+2>=0)
    i+=1
    
m.addConstr(quicksum(x[j] for j in range(48))>=1)
   
'''
for i in range(32):
    m.addConstr(x[i] >= 0)
'''    
m.Params.LogToConsole=True # Show the solution process   
m.optimize() 

v = m.getVars()
for i in range(32+200):
    print('%s %g'%(v[i].varName,v[i].x))
    
cipher = list(range(48))
for i in range(19):
    cipher[i]=int(s[n+i].x)
    print(int(s[n+i].x))
for j in range(29):
    cipher[19+j]=int(l[n+j].x)
    print(int(l[n+j].x))

# the value of the output difference
MASK_VAL = 2 ** 48 - 1;

def rol(x,k):
    return(((x << k) & MASK_VAL) | (x >> (48 - k)));

b=0

for i in range(48):
    b=b^rol(cipher[47-i],i)
print(hex(b))   

#for v in m.getVars():  
#    print('%s %g' % (v.varName, v.x))

print('Obj: %g' % m.objVal)  

time_end=time.time()#Record end time 
print('time cost',time_end-time_start,'s')  



