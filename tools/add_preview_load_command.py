#!/usr/bin/env python3
"""Private lab executable transform for the existing custom XNU port.

Append one explicit compatibility-library load command inside unused Mach-O
header padding. Preserve code, data and entitlements; verify all original
CodeDirectory page hashes and recompute them after the header edit. This is
NOT a valid Apple CMS signature: it targets this lab's existing root platform
policy only. Never publish the input/output Apple executable.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

LIBRARY=b'/Applications/PosterBoard.app/PolarisPreviewCompat.dylib\0'
LEGACY_LIBRARY=b'@executable_path/PolarisPreviewCompat.dylib\0'

def directories(data,allowed_filetypes=(2,)):
    magic,cpu,subtype,filetype,count,length,flags,reserved=struct.unpack_from('<8I',data)
    if magic!=0xfeedfacf or cpu!=0x0100000c or filetype not in allowed_filetypes:
        raise ValueError('Expected thin arm64 Mach-O of the requested type')
    off=32;signature=None;first_section=len(data)
    for i in range(count):
        cmd,size=struct.unpack_from('<II',data,off)
        if size<8 or off+size>32+length:raise ValueError('Invalid command bounds')
        if cmd==0x19:
            nsects=struct.unpack_from('<I',data,off+64)[0]
            if 72+nsects*80>size:raise ValueError('Invalid section table')
            for n in range(nsects):
                p=off+72+n*80
                section_size=struct.unpack_from('<Q',data,p+40)[0]
                section_off=struct.unpack_from('<I',data,p+48)[0]
                if section_size and section_off:first_section=min(first_section,section_off)
        if cmd==0x1d:signature=struct.unpack_from('<II',data,off+8)
        if cmd in (0xc,0x80000018,0x8000001f):
            nameoff=struct.unpack_from('<I',data,off+8)[0]
            if data[off+nameoff:off+size].split(b'\0')[0] in (LIBRARY[:-1],LEGACY_LIBRARY[:-1]):
                raise ValueError('Compatibility load command already present')
        off+=size
    if off!=32+length or signature is None:raise ValueError('Invalid header/signature')
    sig_off,sig_size=signature
    if sig_off+sig_size>len(data):raise ValueError('Signature out of file')
    magic,blob_size,nblobs=struct.unpack_from('>III',data,sig_off)
    if magic!=0xfade0cc0 or blob_size>sig_size or nblobs>64:
        raise ValueError('Invalid embedded signature')
    result=[]
    for i in range(nblobs):
        slot,offset=struct.unpack_from('>II',data,sig_off+12+i*8)
        p=sig_off+offset
        magic,size=struct.unpack_from('>II',data,p)
        if offset+size>blob_size:raise ValueError('Signature blob out of bounds')
        if magic!=0xfade0c02:continue
        hash_off,ident_off,special,nslots,limit=struct.unpack_from('>5I',data,p+16)
        hsize,htype,platform,page_exp=struct.unpack_from('4B',data,p+36)
        algorithms={1:'sha1',2:'sha256',3:'sha256',4:'sha384'}
        if htype not in algorithms or page_exp>20 or limit>sig_off:
            raise ValueError('Unsupported CodeDirectory')
        page_size=1<<page_exp
        if nslots!=(limit+page_size-1)//page_size or hash_off+nslots*hsize>size:
            raise ValueError('Invalid CodeDirectory hash table')
        result.append((p,hash_off,nslots,limit,page_size,hsize,algorithms[htype]))
    if not result:raise ValueError('No CodeDirectory')
    return count,length,first_section,result

def validate_hashes(data,dirs):
    for p,hash_off,nslots,limit,page_size,hsize,algorithm in dirs:
        for i in range(nslots):
            digest=hashlib.new(algorithm,data[i*page_size:min((i+1)*page_size,limit)]).digest()[:hsize]
            actual=data[p+hash_off+i*hsize:p+hash_off+(i+1)*hsize]
            if digest!=actual:raise ValueError(f'CodeDirectory page {i} does not match')

def transform(original):
    count,length,first_section,dirs=directories(original)
    validate_hashes(original,dirs)
    size=(24+len(LIBRARY)+7)&~7
    begin=32+length;end=begin+size
    if end>first_section or any(original[begin:end]):
        raise ValueError('No unused header padding; refusing to shift executable data')
    data=bytearray(original)
    command=struct.pack('<6I',0xc,size,24,0,0x10000,0x10000)+LIBRARY
    data[begin:end]=command.ljust(size,b'\0')
    struct.pack_into('<II',data,16,count+1,length+size)
    changed=[i for i,(a,b) in enumerate(zip(original,data)) if a!=b]
    for p,hash_off,nslots,limit,page_size,hsize,algorithm in dirs:
        for i in range(nslots):
            digest=hashlib.new(algorithm,data[i*page_size:min((i+1)*page_size,limit)]).digest()[:hsize]
            data[p+hash_off+i*hsize:p+hash_off+(i+1)*hsize]=digest
    validate_hashes(data,dirs)
    assert len(data)==len(original)
    assert data[first_section:min(p for p,*_ in dirs)]==original[first_section:min(p for p,*_ in dirs)]
    return bytes(data),{'size':len(data),'load_command_range':[begin,end],
        'header_changes':changed,'code_directories':len(dirs),
        'original_sha256':hashlib.sha256(original).hexdigest(),
        'patched_sha256':hashlib.sha256(data).hexdigest(),
        'page_hashes_verified':True,'executable_sections_unchanged':True}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('input',type=Path);ap.add_argument('output',type=Path)
    args=ap.parse_args();original=args.input.read_bytes();patched,report=transform(original)
    if args.output.exists() and args.output.read_bytes()!=patched:raise FileExistsError(args.output)
    args.output.write_bytes(patched)
    args.output.with_suffix(args.output.suffix+'.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
