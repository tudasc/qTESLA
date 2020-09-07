#!/home/mburger/SageMath/sage -python
from sage.all import*
import sys

def bitlist(a):
    blist=[]
    while(a!=0):
        blist.append(a&1)
        a>>=1
    return blist

def bitrev(i,n):
    bitr=0
    bl = bitlist(i)
    for i in range(len(bitlist(n-1))):
       if (i < len(bl)):
           bitr=2*bitr+bl[i]
       else:
           bitr*=2
    return bitr

def listopn(q,n,c):
    if (is_prime(q)):
        x = primitive_root(q)
        r =  2**32%q
        qinv = 2**32-inverse_mod(q,2**32)
        o = (x**(int((q-1)/n)))%q
        p = (x**(int((q-1)/(2*n))))%q
        oinv = o**(n-1)%q
        pinv = p**(2*n-1)%q
        if (c==0):
            print "#include <stdint.h>\n#include \"params.h\"\n#include \"poly.h\"\n" 
            print "poly zeta ={\n",
            for j in range(n):
                print "%d, "%((p**bitrev(j+1,n)*r)%q),
                if (j%16==15):
                    print "\n",
            print"};\npoly zetainv ={\n",
            for j in range(n):
                print "%d, "%((pinv**(bitrev(j,n)+1)*r)%q),
                if (j%16==15):
                    print "\n",
            print "};"
        elif (c==1):
            #print "\nCopy to params.h\n"
            print "#define PARAM_QINV %d"%(qinv)
            df = q
            ind = 0
            for i in range(int(log(q,2)),33):
                if ((2**i)-(q*int((2**i)/q)) < df):
                    df = ((2**i)-(q*int((2**i)/q)))
                    ind =i
            print "#define PARAM_BARR_MULT %d\n"%(int((2**ind)/q)),
            print "#define PARAM_BARR_DIV %d\n"%(ind),
            print "#define PARAM_R2_INVN %d\n\n"%((r*r*inverse_mod(n,q))%q)

if __name__ == '__main__':
    listopn(int(sys.argv[1]),int(sys.argv[2]),int(sys.argv[3]))


