# coding=utf-8
import binascii
import string

from capstone import *


def _ror(val, bits, bit_size):
    return ((val & (2 ** bit_size - 1)) >> bits % bit_size) | \
           (val << (bit_size - (bits % bit_size)) & (2 ** bit_size - 1))


__ROR4__ = lambda val, bits: _ror(val, bits, 32)

HIBYTE = lambda val: (val & 0xff00) >> 8
HIWORD = lambda val: (val & 0xffff0000) >> 16

buf_base = list(b"ATATATATATATATAT")
data_23000 = list(open("data_23000", "rb").read())


def nextint(i):
    return __ROR4__(i + 1337, 25) ^ 0xDEADBEEF


def decrypt(base, key, flag):
    for i in range(15):
        if i & 1:
            base[i] = HIBYTE(flag) ^ key[i]
        else:
            base[i] = (flag & 0xff) ^ key[i]


def disass(f, mode=CS_MODE_THUMB):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | mode)
    code = binascii.unhexlify(f)
    for i in md.disasm(code, 0x22000, 2):
        if i.mnemonic == "bx" and i.op_str == "lr":
            break
        print("%-8s\t\t%s\t%s" % (binascii.hexlify(i.bytes).decode(), i.mnemonic, i.op_str))


def main():
    instr = 0x156a
    tab256 = set()
    while True:
        while True:
            instr = nextint(instr)
            offset = (instr & 0xffff) >> 1
            if offset not in tab256:
                tab256.add(offset)
                break

        #######
        buf = buf_base[:]
        decrypt(buf, data_23000[offset * 16:], HIWORD(instr))
        code = "".join(list(map(lambda x: "%02x" % x, buf)))
        if code[:4] == "fecc":  # End of code
            break
        if (instr & 1) != 0:
            disass(code, CS_MODE_THUMB)
        else:
            disass(code, CS_MODE_ARM)


if __name__ == '__main__':
    main()
