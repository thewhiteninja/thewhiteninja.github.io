# coding=utf-8


def bin2str(s):
    return "".join([chr(int(s[i:i + 8], 2)) for i in range(0, len(s), 8)])


def main():
    data_400273 = open("400273", "rb").read()
    data_40022B = open("40022B", "rb").read()

    flag_bitstream = ""
    for i in range(576)[::-1]:
        flag_bitstream += "1" if (data_40022B[i // 8] >> (i % 8)) & 1 ^ data_400273[8 * (i // 8) + i % 8] else "0"

    print(bin2str(flag_bitstream)[::-1])


if __name__ == '__main__':
    main()
