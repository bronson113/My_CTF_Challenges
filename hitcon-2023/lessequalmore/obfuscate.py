import sys

if len(sys.argv) < 3:
    print("obfuscate.py [input file] [output file]")
with open(sys.argv[1], 'r') as ifile:
    with open(sys.argv[2], 'w') as ofile:
        nums = ifile.read().split()
        for i, num in enumerate(nums):
            ofile.write(f"{num}")
            if i%30 == 29:
                ofile.write("\n")
            else:
                ofile.write(" ")




