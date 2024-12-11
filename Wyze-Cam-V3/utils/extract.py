import re
import serial
import time
import sys
# serial object
ser = None

# (start, size)
partitions = {
    "boot": (0x00000,0x40000),
    "kernel": (0x40000,0x1F0000),
    "rootfs": (0x230000,0x3D0000),
    "app": (0x600000,0x3D0000),
    "kback": (0x9D0000,0x1F0000),
    "aback": (0xBC0000,0x3D0000),
    "cfg": (0xF90000,0x60000),
    "para": (0xFF0000,0x10000),
}

def print_help():
    print("Usage : ./uboot-extract.py <uart-device> <partition>")
    print("Example : ./uboot-extract.py /dev/ttyUSB0 cfg")
    print(f"Available partitions : {','.join(part for part in partitions)}\n")
    exit(1)

def generate_oneliner():
    command = "sf probe\n"
    for part,data in partitions.items():
        offset,size = data
        command += f"sf read 0x80000000 0x{offset:X} 0x{size:X};"
        command += f"md.b 0x80000000 0x{size:X};"
    print(command)

def main(device,partition):

    global ser

    offset,size = 0x0, 0x0
    out = b''

    if partition in partitions:
        offset, size = partitions[partition]
    else:
        print(f"Error, partition {partition} not found")
        print_help()

    if device is not None:
        ser = serial.Serial(device,115200, timeout=1)
        ser.isOpen()

    while ser.inWaiting() > 0:
        # empty any buffered data
        null = ser.read(1)

    print(f"Reading : {partition} : from 0x{offset:X} with size 0x{size:X}\n")

    # load partition in memory
    command = f"sf probe; sf read 0x80000000 0x{offset:X} 0x{size:X}\r\n"
    print(">>>>",command)
    ser.write(command.encode('ascii'))
    time.sleep(0.5)
    while ser.inWaiting() > 0:
        out += ser.read(1)
    line = ""
    for c in out.decode('ascii'):
        if c == '\n':
            print("<<<<",line)
            line = ''
        else:
            line += c

    # read data loaded in memory
    command = f"md.b 0x80000000 0x{size:X}\r\n"
    print("\n>>>>",command)
    ser.write(command.encode('ascii'))
    time.sleep(0.5)
    data = ser.readline()

    with open(f"{partition}.bin","wb") as file:
        reg = r'^[0-f]{8}:((\s+[0-f]{2}){16})\s{4}.*$'
        size_collected = 0
        while size_collected < size:
            data = b''
            data_extracted = None
            if ser.in_waiting > 0:
                data = ser.readline()
            # print("<<<<",data)
            if data != b'':
                match = re.match(reg,data.decode('ascii',errors="ignore"))
                if match:
                    data_extracted = bytes.fromhex(match.group(1))
                else:
                    # flush some data still in queue
                    data = data.decode('ascii')
                    match = re.match(r'^.*: (.*)\s{4}.*$',data)
                    if match:
                        data = match.group(1).replace('\\x','').replace(' ','')
                        try:
                            data_extracted = bytes.fromhex(data)
                        except:
                            print(data,"data crash")
                            exit()

                if data_extracted is not None:
                    file.write(data_extracted)
                    size_collected += len(data_extracted)
                    print(f"Progress : {size_collected} B / {size} B ({(100*size_collected)/size:.1f}%)",end='\r', flush=True)

        print(f"\nFinished reading {partition}, saved to {partition}.bin")

if __name__ == "__main__":
    print()
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "oneliner":
            generate_oneliner()
        elif len(sys.argv) != 3:
            print_help()
        elif len(sys.argv) == 3:
            main(device=sys.argv[1],partition=sys.argv[2])
        else:
            print_help()
    except KeyboardInterrupt:
        print("Ctrl + C pressed, exiting...")
    finally:
        if ser is not None:
            # to stop any current comment
            ser.write(b'\x03') # interrupt
            ser.write(b'?\n')
            while ser.inWaiting():
                b = ser.read(1)
            ser.close()    
    print()
