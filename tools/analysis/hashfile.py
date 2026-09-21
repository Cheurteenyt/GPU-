import hashlib,sys
print(hashlib.sha512(open(sys.argv[1],"rb").read()).hexdigest())
