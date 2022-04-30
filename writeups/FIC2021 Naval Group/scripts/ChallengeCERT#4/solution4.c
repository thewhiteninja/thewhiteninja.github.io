#include <iostream>

char unk_21050[36] = { 0 };
char flag[43] = { 0 };

int load_unknown_21050()
{
	FILE* f;
	fopen_s(&f, "unk_21050", "rb");
	if (f)
	{
		fread(unk_21050, 36, 1, f);
		fclose(f);
	}
	else
	{
		printf("Failed to read unk_21050");
		return 0;
	}
	return 1;
}

uint32_t unk(int i)
{
	return *((uint32_t*)(unk_21050 + i));
}

int main()
{
	int i;

	if (!load_unknown_21050())
		return 1;


	*((uint32_t*)(flag + 7)) = unk(8) ^ 0xffffffff;
	*((uint32_t*)(flag + 11)) = unk(0) ^ 0xffffffff;

	*((uint32_t*)(flag + 0)) = *((uint32_t*)(flag + 10));
	*((uint32_t*)(flag + 4)) |= *((uint32_t*)(flag + 14));

	*((uint16_t*)(flag + 18)) = *((uint16_t*)(flag + 8));


	for (i = 0; i <= 0xffff; i++) {

		if ((((i * 2) + i) * 2) + i == unk(32))
		{
			*((uint16_t*)(flag + 5)) = i;
		}
	}

	*((uint32_t*)(flag + 14)) = *((uint32_t*)(flag + 4));

	*((uint32_t*)(flag + 24)) = _rotl(unk(28), 11);

	*((uint32_t*)(flag + 20)) = unk(16) - *((uint32_t*)(flag + 24));

	i = 1;
	uint32_t unk4 = unk(4);
	uint32_t unk12 = unk(12);
	uint32_t unk20 = unk(20);
	uint32_t unk24 = unk(24);

	while (i++)
	{
		if (((i & unk4) == unk24) && (((i & unk20) == unk12)))
		{
			*((uint32_t*)(flag + 28)) = i;
			break;
		}
	}

	flag[32] = flag[31] + 36;
	flag[33] = flag[32] + 10;
	flag[34] = flag[33] - 59;
	flag[35] = flag[34] + 32;
	flag[36] = flag[35] - 30;
	flag[37] = flag[36] + 42;
	flag[38] = flag[37] - 62;


	for (i = 39; i < 42; i++)
	{
		flag[i] = flag[38];
	}

	for (i = 0; i < 42; i++) printf("%c", flag[i] ? flag[i] : '_');
	printf("\n");

	return 0;
}

'''
Here are the secret plans:

                 ________
            _,.-Y  |  |  Y-._
        .-~"   ||  |  |  |   "-.
        I" ""=="|" !""! "|"[]""|     _____
        L__  [] |..------|:   _[----I" .-{"-.
       I___|  ..| l______|l_ [__L]_[I_/r(=}=-P
      [L______L_[________]______j~  '-=c_]/=-^
       \_I_j.--.\==I|I==_/.--L_]
         [_((==)[`-----"](==)j
            I--I"~~"""~~"I--I
            |[]|         |[]|
            l__j         l__j
            |!!|         |!!|
            |..|         |..|
            ([])         ([])
            ]--[         ]--[
            [_L]         [_L]
           /|..|\       /|..|\
          `=}--{='     `=}--{='
         .-^--r-^-.   .-^--r-^-.

----------------------------------------
Well done !
----------------------------------------
'''

if __name__ == '__main__':
    main()
