import argparse
import struct
from pathlib import Path


def building_args():
    parser = argparse.ArgumentParser(description="PE analizer")
    parser.add_argument("--target","-t",required=True,type=str,description="select a file for analiyer")
    return parser.parse_args()

class catpe:
    def __init__(self,target:str):
        self.target = target

    def run(self):
        with open(self.target,"rb") as f:
            data = f.read()
            mz_header = data[:2]
        
            if mz_header == b"MZ":
                pass
            else:
                print("invalid pe")
                quit()

            offset_pe = struct.unpack_from("<I", data, 0x3C)[0]

            if offset_pe > len(data):
                print("Dos header invalid")
                quit() 

    
            pe_signature = data[offset_pe:offset_pe + 4]
            
            if pe_signature != b"PE\x00\x00":
                print("pe signature invalid")
                quit()

            coff = offset_pe + 4
            machine, sessions, timestamp = struct.unpack_from("<HHI", data, coff)
            print("file:",self.target)
            print("------------------")
            print("mz header:ok")
            print(f"offset:",offset_pe)
            print("machine:",hex(machine))
            print("sessions number:",sessions)
            print("timetamp:",timestamp)
            print("------------------")
            print("file size :", len(data))
            print("e_lfanew:", hex(offset_pe))

            pe_signature = data[offset_pe:offset_pe + 4]
            print("signature:", repr(pe_signature))
            print("Bytes hex:", pe_signature.hex())


def cli():
    args = building_args()
    catpe_instance = catpe(args.target)
    catpe_instance.run()

