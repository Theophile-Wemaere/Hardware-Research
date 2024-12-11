import re
import sys

reg = r'^[0-f]{8}:((\s+[0-f]{2}){16})\s{4}.*$'

def write_file(part,line):
    with open(f"{part}.bin","ab") as output:
        match = re.match(reg,line)
        if match:
            output.write(bytes.fromhex(match.group(1)))

def main(dumpfile):

    if len(sys.argv) != 2:
        print("Please specify file to parse")

    # first dump all the data to output.fw for analysis with binwalk
    with open("firmware.bin","wb") as output:
        with open(dumpfile,'r') as file:
            for line in file:
                match = re.match(reg,line)
                if match:
                    output.write(bytes.fromhex(match.group(1)))
    print("Dumped all data to firmware.bin")

    parts = ["boot","kernel","rootfs","app","kback","aback","cfg","para"]
    c = 0
    is_dump = False
    start = True
    part = ""
    with open(dumpfile,'r') as file:
        for line in file:
            if line.find("SF: ") != -1:
                is_dump = False
            elif line.find("--->read spend") != -1:
                # next line is dump start
                is_dump = True
                if start:
                    start = False
                else:
                    c += 1
                part=parts[c]
                print(f"Reading dump for part {part}, saving to {part}.bin")
            else:
                write_file(part,line)

if __name__ == "__main__":
    print()
    try:
        if len(sys.argv) != 2:
            print("Please specify a file to analyse\nExample : python translate.py dump.txt")
        else:
            main(sys.argv[1])
    except KeyboardInterrupt:
        exit(0)
    print()