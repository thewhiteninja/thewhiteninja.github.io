# FIC 2021 - Challenge Naval Group

Pour le [#FIC2021](https://www.forum-fic.com/en/home.htm), [Naval Group](https://www.naval-group.com) a publié un challenge sur [Twitter](https://twitter.com/navalgroup/status/1435149462331183106?s=20) avec de nombreux lots à gagner !

Le QR code contient un lien vers la première étape du challenge :)



![challenge](images/qrcode.png)

















# Challenge 1.0

Rien à faire pour cette étape, on récupère juste le règlement du concours et un lien vers l'étape 1.1.

# Challenge 1.1

Pour cette étape, on nous donne un petit binaire ELF 64 bits nommé **x**.


```powershell
PS D:\FIC2021 Chall\ChallengeCERT#1.1> file .\x
.\x: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

Une seule fonction intéressante nommée `_start`.

Voici le code renommé et nettoyé :

```c
signed __int64 start()
{
  int v0; // er14
  signed __int64 v1; // rax
  unsigned __int64 v2; // rcx

  v0 = 0;
  v1 = sys_read(0, &password, 0x48uLL);
  v2 = 575LL;
  do
  {
    if ( (((encrypted[v2 / 8] ^ password[v2 / 8]) >> (v2 % 8)) & 1) != bitstream[8 * (v2 / 8) + v2 % 8] )
      v0 |= 1u;
    --v2;
  }
  while ( v2 );
  return sys_exit(v0);
```

Ça commence par lire le mot de passe de 72 caractères.
Puis, le flag est déchiffré avec ce mot de passe.

Chaque bit de **encrypted** est xoré avec son bit correspondant dans **password** et comparé au **bitsream**.
Le **bitstream** fait 576 bits, ce qui donne bien 8 bits par caractère.

On peut voir que la comparaison est faite du dernier caractère au premier.

Il suffit de xorer les bits d'**encrypted** avec ceux du **bitstream** pour retrouver bon **password**.

Ce qui donne en Python :snake:

```python
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
```

On obtient finalement l'URL vers la prochaine étape.

Tous les flags semblent être une URL https://dropfile.naval-group.com/pfv2-sharing/sharings/[random].[random]



# Challenge 2

Pour cette étape, nous avons un dump mémoire d'une machine infectée et nous devons trouver le hash sha256 du binaire malveillant.

Un programme **check_hash** est fourni pour vérifier le hash.

## Dump mémoire

Avec [Volatility](https://www.volatilityfoundation.org/), on peut voir que l'image mémoire semble provenir d'un **Windows 10 x86**.

```powershell
PS D:\FIC2021 Chall\ChallengeCERT#2> volatility_2.6_win64_standalone.exe imageinfo -f .\memory.img
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x86_10586, Win10x86, Win81U1x86, Win8SP1x86, Win8SP0x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (D:\Torrents\Nouveau dossier\ChallengeCERT#2\memory.img)
                      PAE type : PAE
                           DTB : 0x1a8000L
                          KDBG : 0x82461820L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0x8248b000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2016-08-17 12:00:47 UTC+0000
     Image local date and time : 2016-08-17 14:00:47 +0200
```

On peut maintenant lister les processus.

    PS D:\FIC2021 Chall\ChallengeCERT#2> volatility_2.6_win64_standalone.exe pslist --profile=Win10x86 -f .\memory.img
    Volatility Foundation Volatility Framework 2.6
    Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
    ---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
    0x868a7700                           4      0 24...2        0 ------      0 2016-08-16 12:54:24 UTC+0000
    0x8d2af5c0 `U+?smss.exe            244      4 23...6        0 ------      0 2016-08-16 12:54:24 UTC+0000
    0x8f7e3040 `\♠?csrss.exe           324    316 33...2        0      0      0 2016-08-16 12:54:27 UTC+0000
    0x9487c640                         388    244 24...8 --------      1      0 2016-08-16 12:54:28 UTC+0000   2016-08-16 
    0x8b9bf300 ►???wininit.exe         396    316 33...6        0      0      0 2016-08-16 12:54:28 UTC+0000
    0x8f71d2c0 @???csrss.exe           408    388 33...2        0      1      0 2016-08-16 12:54:28 UTC+0000
    0x94863c40 ????winlogon.exe        460    388 33...8        0      1      0 2016-08-16 12:54:28 UTC+0000
    0x8b9bc300?)?services.exe        488    396 26...0        0      0      0 2016-08-16 12:54:29 UTC+0000
    0x948c3040 ?-??lsass.exe           516    396 33...0        0      0      0 2016-08-16 12:54:29 UTC+0000
    0x948fb180 p???svchost.exe         576    488 24...6        0      0      0 2016-08-16 12:54:30 UTC+0000
    0x94954380 ?I??svchost.exe         620    488 33...8        0      0      0 2016-08-16 12:54:30 UTC+0000
    0x949bdc40 0♠??dwm.exe             716    460 33...0        0      1      0 2016-08-16 12:54:31 UTC+0000
    0x949b08c0 XV??svchost.exe         764    488 33...2        0      0      0 2016-08-16 12:54:31 UTC+0000
    0x9495d6c0 ????svchost.exe         800    488 35...0        0      0      0 2016-08-16 12:54:31 UTC+0000
    0x949d3040 0S??svchost.exe         848    488 33...4        0      0      0 2016-08-16 12:54:31 UTC+0000
    0x949d3c40 ????svchost.exe         856    488 41...2        0      0      0 2016-08-16 12:54:31 UTC+0000
    0x949faac0???svchost.exe         896    488 41...8        0      0      0 2016-08-16 12:54:31 UTC+0000
    0x94ca1700 ??s?svchost.exe        1068    488 26...2        0      0      0 2016-08-16 12:54:32 UTC+0000
    0x94caf040 ????svchost.exe        1132    488 24...2        0      0      0 2016-08-16 12:54:32 UTC+0000
    0x9a018040 ??☺?spoolsv.exe        1212    488 31...8        0      0      0 2016-08-16 12:54:32 UTC+0000
    0x9a039040 @?♥?svchost.exe        1380    488 26...2        0      0      0 2016-08-16 12:54:34 UTC+0000
    0x9a118380 h?◄?svchost.exe        1540    488 33...4        0      0      0 2016-08-16 12:54:34 UTC+0000
    0x9a10cb00 `??wlms.exe           1572    488 33...4        0      0      0 2016-08-16 12:54:34 UTC+0000
    0x9c64f980 8?→?sihost.exe          688    800 33...4        0      1      0 2016-08-16 12:55:35 UTC+0000
    0x8c13ea00 X!v?taskhostw.ex        268    800 33...0        0      1      0 2016-08-16 12:55:36 UTC+0000
    0x8ad6c040                        1556    460 23...6 --------      1      0 2016-08-16 12:55:36 UTC+0000   2016-08-16
    0x8ac4a040 ????explorer.exe       2068   1556 35...4        0      1      0 2016-08-16 12:55:36 UTC+0000
    0x8ad60940 xj??RuntimeBroke       2196    576 38...2        0      1      0 2016-08-16 12:55:37 UTC+0000
    0x8ad5f040 ????SkypeHost.ex       2220    576 24...2        0      1      0 2016-08-16 12:55:37 UTC+0000
    0x8ad22c40  l??ShellExperie       2432    576 33...8        0      1      0 2016-08-16 12:55:39 UTC+0000
    0x8b8520c0 ?W??SearchIndexe       2532    488 33...0        0      0      0 2016-08-16 12:55:40 UTC+0000
    0x8b8fb8c0 hX5?OneDrive.exe       3592   2068 31...0        0      1      0 2016-08-16 12:55:57 UTC+0000
    0x9c68ec40 ????fontdrvhost.       4428    460 33...4        0      1      0 2016-08-16 12:57:09 UTC+0000
    0x9c728480 H?v?svchost.exe        4900    488 24...6        0      1      0 2016-08-16 12:57:21 UTC+0000
    0x8ad86c40 `E??Skype.exe          5128   4696 38...8        0      1      0 2016-08-16 12:57:42 UTC+0000
    0x8c0c9240 ???TrustedInsta       6108    488 24...4        0      0      0 2016-08-16 12:58:24 UTC+0000
    0x8c0ba9c0 0?@?TiWorker.exe       6140    576 24...2        0      0      0 2016-08-16 12:58:25 UTC+0000
    0x9d489780 ????SystemSettin       2144    576 26...4        0      1      0 2016-08-16 12:59:36 UTC+0000
    0x9499ac40 ?i??ApplicationF       1696    576 24...4        0      1      0 2016-08-16 12:59:48 UTC+0000
    0x9c629300 ??h?SystemSettin       5268   5252 33...6        0      1      0 2016-08-16 12:59:51 UTC+0000
    0xb0d47780 ?o??svchost.exe        4888   4748 33...4        0      1      0 2016-08-16 13:02:57 UTC+0000
    0x9d5e74c0 ????explorer.exe       4872   4748 33...8        0      1      0 2016-08-16 13:02:58 UTC+0000
    0x9c7d7c40 ??*?svchost.exe        2168   5860 33...0        0      1      0 2016-08-16 13:03:04 UTC+0000
    0xb0c96740 ?-[?update.exe         5172   5860 24...2        0      1      0 2016-08-16 13:03:04 UTC+0000
    0xd0d9f600                        1976   5172 35...6 --------      1      0 2016-08-16 13:04:47 UTC+0000   2016-08-16 
    0x9d5ba900                         736   5172 35...6 --------      1      0 2016-08-16 13:07:40 UTC+0000   2016-08-16 
    0xbac89640 p???SystemSettin       4968    576 23...2        0      1      0 2016-08-16 13:41:14 UTC+0000
    0xbad4b040                        2748   5172 31...2 --------      1      0 2016-08-16 13:50:51 UTC+0000   2016-08-16 
    0xbf755c40                        5280   5172 41...4 --------      1      0 2016-08-16 14:17:24 UTC+0000   2016-08-16 
    0x8b8c44c0                         868   5172 35...2 --------      1      0 2016-08-16 14:19:45 UTC+0000   2016-08-16 
    0xd53d2c40                        3540   5172 35...6 --------      1      0 2016-08-16 14:23:05 UTC+0000   2016-08-16 
    0xd5321480 ????SearchUI.exe       7360    576 31...6        0      1      0 2016-08-16 18:13:21 UTC+0000
    0x9c6a8040 H ??audiodg.exe       18084    848 26...4        0      0      0 2016-08-17 12:00:20 UTC+0000
    0xc8606c40 ??RamCapture.e      16740   2068 26...6        0      1      0 2016-08-17 12:00:36 UTC+0000
    0xd53a3500 ?6o?conhost.exe       16756  16740 33...6        0      1      0 2016-08-17 12:00:36 UTC+0000
    0x9c61a300 8)??SearchProtoc      15756   2532 33...4        0 ------      0 2016-08-17 12:00:50 UTC+0000
    0xc7fa2a40 ?3p?SearchFilter      14288   2532 33...4        0 ------      0 2016-08-17 12:00:50 UTC+0000
    0xe2df3040 ?\??MusNotificat      16968    800 25...4        0 ------      0 2016-08-18 09:25:38 UTC+0000
    0xb0df7040                           0      0 29...0 -------- ------      0

## Binaire malveillant

Tout n'est pas très clair, mais le seul binaire avec un nom un peu suspect semble être **update.exe**.
De toute façon, on pourrait très bien dumper tous les processus et essayer chaque hash :)

```powershell
PS D:\FIC2021 Chall\ChallengeCERT#2> volatility_2.6_win64_standalone.exe procdump --profile=Win10x86 -f .\memory.img -D .\ -p 5172
Volatility Foundation Volatility Framework 2.6
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0xb0c96740 0x01610000 ?-[?update.exe       OK: executable.5172.exe
```

Puis on calcule le hash sha256.    
```powershell
PS D:\FIC2021 Chall\ChallengeCERT#2> sha256sum.exe .\executable.5172.exe
\166d8eb95ac704b6dc2bad8ffa8fb492e84fde52801a3dec551cc79e9c644e50 *.\\executable.5172.exe
```

Et on passe sous Linux (dans Windows :heart:) pour vérifier le hash.

```powershell
PS D:\FIC2021 Chall\ChallengeCERT#2> bash
debian@osef:/mnt/ChallengeCERT#2$ ./check_hash
Please input the SHA256 hash:
166d8eb95ac704b6dc2bad8ffa8fb492e84fde52801a3dec551cc79e9c644e50
----------------------------------------
Well done !
----------------------------------------
```

## Bonus

Le binaire est en fait **[Xtreme RAT](https://www.virustotal.com/gui/file/166d8eb95ac704b6dc2bad8ffa8fb492e84fde52801a3dec551cc79e9c644e50/)** et il est fait en [Delphi](https://www.embarcadero.com/products/delphi) ! Mais alors il y a une autre personne qui aime Delphi en 2021 ? :open_mouth:

On peut aller voir le `timestamp` du binaire et on trouve `2A425E19` ce qui correspond au `1992-06-19 22:22:17` ... un peu étrange parce que l'aventure Delphi a commencé vers 1995 :smile:.

En fait, il semblerait que les anciens compilateurs Delphi (4 à 2006) aient un "bug" où le `timestamp` soit une valeur fixe préconfigurée au lieu de la date de compilation :scream:. On a donc tout un tas de binaire avec un `timestamp` à `2A425E19` et il suffit de chercher sur [Google](https://www.google.com/search?q=2A425E19+timestamp) pour voir pas mal de ces binaires dans des rapports de crash.

Mais alors il date de quand ce binaire ? :man_shrugging:

Pour ce binaire, il y a d'autres timestamps dans la partie des ressources (`_IMAGE_RESOURCE_DIRECTORY`). On trouve la valeur `446B4C0F` qui correspond au `2006-05-17 16:15:11`. 

Plus d'infos sur : https://0xc0decafe.com/malware-analyst-guide-to-pe-timestamps/#Delphi_timestamps



# Challenge 3

On passe maintenant à un reverse Windows avec un fichier nommé **cell.exe**.

(J'ai renommé quelques fonctions pour que ce soit plus simple)

Un petit test rapide pour voir ce qu'il fait.

```powershell
PS D:\FIC2021 Chall\ChallengeCERT#3> .\cell.exe
Enter the password:
123456
Fail!
```

Alors peut-être avec une autre URL.

```powershell
PS D:\FIC2021 Chall\ChallengeCERT#3> .\cell.exe
Enter the password:
https://dropfile.naval-group.com/pfv2-sharing/sharings/aaaaaaaa.aaaaaaaa
b13220621fd3a7f32e2f163df5c01cbb06f7d8e4951ac01d9cb650b70272396fcb8f6c422be5c7f729420051df07c5b2c960294ffb0a5514b4be071790b82f451830663ffdaa16b8
54108f28cfe1c3f116974a9efadfcc5d737bea600a4d5fce8c5a265b783098b7c5a7b51895e2d3fb1098ff24ef73d2d140af9087fd642a48585ef34b865b97924b97229ffed4cb5a
29c6271247ecd9f44b0b850f7d6fc52eb1bdf42fe406afc7252c822dbb960a5bd2c3da4a0ae961fd460a7f0077b1e1649e578633fea194032b2f7185b22d8b80058b090fff6845ac
90d2834013f468f90565b267beb7d21754def997e1f357d302143896dd8ae42de159ec04e570acfe92e43f7f3bd4eca00e2bb291ff4c89f91517b4b2d096a5bff2a56067ffb312d5
8661399fc1f9327872a2d023df5be0cba86f788becf1abe178c99a0b6ea56196eca8f5f062b6547f01619fbf1de8744fe695d104ff8420f84a4bd851660b42dff142af23ffd1416a
322c188fdcf8103b31496789efadee45d337ba25f474d5ecba408ce5b742ac8b74527af7295a293f7cac8fdf4ef33907e30ae4707fb18e7b0405eb24a2e5996ff4995709ffe49cb5
Fail!
```

C'est déjà un peu mieux.

On peut aller voir le code qui fait ça (*sub_401B9D*).

```c
int __cdecl sub_401B9D(char a1)
{
  FILE *Stream; // eax
  DWORD v3; // eax
  CHAR Name[30]; // [esp+1Fh] [ebp-449h] BYREF
  char state[515]; // [esp+3Dh] [ebp-42Bh] BYREF
  char Str[500]; // [esp+240h] [ebp-228h] BYREF
  BOOL v7; // [esp+434h] [ebp-34h]
  HANDLE hHandle; // [esp+438h] [ebp-30h]
  int m; // [esp+43Ch] [ebp-2Ch]
  char v10[4]; // [esp+440h] [ebp-28h]
  int k; // [esp+444h] [ebp-24h]
  int j; // [esp+448h] [ebp-20h]
  int i; // [esp+44Ch] [ebp-1Ch]
  char *v14; // [esp+458h] [ebp-10h]

  v14 = &a1;
  sub_401F60();
  memset(&state[15], 0, 500);
  puts("Enter the password:");
  fgets(Str, 500, stdin);
  Str[strcspn(Str, "\n")] = 0;
  if ( strlen(Str) == 72 )
  {
    for ( i = 0; i <= 71; ++i )
      Str[i] ^= key1[i];
    for ( j = 0; j <= 71; ++j )
      printf("%02x", Str[j]);
    putchar(10);
    initEvent(Str);
    for ( k = 0; k <= 4; ++k )
    {
      memset(&state[15], 0, 0x48u);
      transformPass();
      *v10 = 0;
      while ( *v10 <= 575 )
      {
        strcpy(state, "Global\\cell_%d");
        printflike(Name, 0x1Eu, state, v10[0]);
        hHandle = OpenEventA(0x1F0003u, 0, Name);
        v3 = WaitForSingleObject(hHandle, 0xAu);
        if ( v3 != WAIT_TIMEOUT )
          state[*v10 / 8 + 15] |= 1 << (7 - *v10 % 8);
        ++*v10;
      }
      for ( m = 0; m <= 71; ++m )
        printf("%02x", state[m + 15]);
      putchar(10);
    }
    if ( !memcmp(&unk_404080, &state[15], 0x48u) )
      puts("Congratulations!");
    else
      puts("Fail!");
    return 0;
  }
  else
  {
    puts("Fail!");
    return 0;
  }
}
```

Ça commence par demander le mot de passe et le stocke à **&state[15]**.

```c
memset(&state[15], 0, 500);
puts("Enter the password:");
fgets(Str, 500, stdin);
```

Ensuite, on vérifie que le mot de passe fait bien 72 caractères.

```c
if ( strlen(Str) == 72 )
{
...
}
else
{
  puts("Fail!");
  return 0;
}
```

## Première transformation

Si la taille est bonne, le mot de passe est xoré avec une clé située *@00404020* (key1).

```asciiarmor
D9 46 54 12 6C E9 88 DC 4A 5D 79 4D 93 A9 70 DE
28 99 B9 92 F4 76 ED 7A EE D9 25 C7 2C 11 56 02
E4 FF 0A 34 19 C8 B4 9F 48 30 69 3F B8 28 B6 DA
A8 12 40 21 9C 79 7A 75 D5 DF 66 76 F1 D9 4E 6B
79 51 07 5E 9C CB 77 D9
```

On a bien une clé de 72 caractères.

Une fois xorée, le résultat est affiché. Dans les tests fais plus haut, cela correspond à :

```asciiarmor
b13220621fd3a7f32e2f163df5c01cbb06f7d8e4951ac01d9cb650b70272396fcb8f6c422be5c7f729420051df07c5b2c960294ffb0a5514b4be071790b82f451830663ffdaa16b8
```

## Boucle de transformations

Maintenant, ça se complique !
On voit bien les 5 boucles qui vont transformer et afficher notre mot de passe, mais difficile de dire comment comme ça.
En tout cas, à la fin, on vérifie que le résultat correspond bien à celui attendu qui est stocké à *@404080*.

```c
if ( !memcmp(&unk_404080, &state[15], 0x48u) )
  puts("Congratulations!");
else
  puts("Fail!");
```

Revenons à notre boucle.

## Initialisation

On commence par la fonction *@401564* (initEvents).

```c
int __cdecl initEvents(int a1)
{
  CHAR Name[30]; // [esp+1Bh] [ebp-4Dh] BYREF
  char v3[16]; // [esp+39h] [ebp-2Fh] BYREF
  char bInitialState[19]; // [esp+49h] [ebp-1Fh] BYREF
  char v5[4]; // [esp+5Ch] [ebp-Ch]

  strcpy(bInitialState, "Global\\cell_%d");
  strcpy(v3, "Global\\ncell_%d");
  *v5 = 0;
  while ( *v5 <= 575 )
  {
    printflike(Name, 0x1Eu, bInitialState, v5[0]);
    *&bInitialState[15] = (*(*v5 / 8 + a1) >> (7 - *v5 % 8)) & 1;
    CreateEventA(0, 1, *&bInitialState[15], Name);
    printflike(Name, 0x1Eu, v3, v5[0]);
    CreateEventA(0, 1, 0, Name);
    ++*v5;
  }
  return 0;
}
```

On retrouve une boucle de 576 tours. Apparemment, il y aura encore de la comparaison bit à bit :thinking:.

Pour chaque bit de **password**, on va créer un Event nommé **Global\\cell_x** avec ce bit en paramètre.

    *&bInitialState[15] = (*(*v5 / 8 + a1) >> (7 - *v5 % 8)) & 1;

Quant à l'autre Event, **Global\\ncell_0**, il est créé, mais avec un paramètre nul (0).

Au final, cette fonction va donc créer 576 Events nommés **Global\\cell_0**, **Global\\cell_1**, ... avec les bits de
**password**, puis 576 Events "vides" nommés **Global\\ncell_0**, **Global\\ncell_1**, ...

Les **Global\\ncell_x** serviront à stocker le résultat d'une operation/transformation.

## Transformation

On revient à la fonction précédente avec nos 5 boucles.

```c
for ( k = 0; k <= 4; ++k )
{
  memset(&state[15], 0, 0x48u);
  transformPass();
  *v10 = 0;
  while ( *v10 <= 575 )
  {
    strcpy(state, "Global\\cell_%d");
    printflike(Name, 0x1Eu, state, v10[0]);
    hHandle = OpenEventA(0x1F0003u, 0, Name);
    v3 = WaitForSingleObject(hHandle, 0xAu);
    if ( v3 != WAIT_TIMEOUT )
      state[*v10 / 8 + 15] |= 1 << (7 - *v10 % 8);
    ++*v10;
  }
  for ( m = 0; m <= 71; ++m )
    printf("%02x", state[m + 15]);
  putchar(10);
}
```

A chaque boucle, on va transformer le **password**.

Puis on récupère les nouveaux bits depuis **Global\\cell_x** en faisant un **OpenEvent** et on met à jour le bit correspondant de **state**.

À chaque boucle, on affiche le nouvel état.

```asciiarmor
54108f28cfe1c3f116974a9efadfcc5d737bea600a4d5fce8c5a265b783098b7c5a7b51895e2d3fb1098ff24ef73d2d140af9087fd642a48585ef34b865b97924b97229ffed4cb5a
29c6271247ecd9f44b0b850f7d6fc52eb1bdf42fe406afc7252c822dbb960a5bd2c3da4a0ae961fd460a7f0077b1e1649e578633fea194032b2f7185b22d8b80058b090fff6845ac
90d2834013f468f90565b267beb7d21754def997e1f357d302143896dd8ae42de159ec04e570acfe92e43f7f3bd4eca00e2bb291ff4c89f91517b4b2d096a5bff2a56067ffb312d5
8661399fc1f9327872a2d023df5be0cba86f788becf1abe178c99a0b6ea56196eca8f5f062b6547f01619fbf1de8744fe695d104ff8420f84a4bd851660b42dff142af23ffd1416a
322c188fdcf8103b31496789efadee45d337ba25f474d5ecba408ce5b742ac8b74527af7295a293f7cac8fdf4ef33907e30ae4707fb18e7b0405eb24a2e5996ff4995709ffe49cb5
```

Il faut que le dernier état soit égal à celui harcodé en *@404080*.

```asciiarmor
f22c188fdcf8103b31496789efadee45d337ba25f474d5ecba408ce5b742ac8b74527af7295a293f7cac8fdf4ef33907e30ae4707fb18e2596de344bc8befc1518c8b2897f61096a
```

On peut voir qu'une bonne partie correspond déjà. Mais ni la fin (normal) et ni le premier octet :thinking:

On verra après pourquoi ...

## Event et bits 

Sans trop rentrer dans les détails, un Event a un nom et deux états possibles.

> Les Events sont un moyen de faire de la synchronisation. Ils sont même partagés entre les processus.
> Un processus pour créer un Event et attendre cet Event pour lire quelque chose. Et un autre processus peut écrire
> quelque part, puis faire un **SetEvent** pour signaler à l'autre processus qu'il peut commencer à lire.
>
> Plus d'infos ici: https://docs.microsoft.com/en-us/windows/win32/sync/event-objects
>
> On le crée avec **CreateEvent** et on modifie son état avec **SetEvent** pour le mettre à "Vrai" ou **ResetEvent** pour l'état "Faux".
> Pour connaitre l'état d'un Event, on peut utiliser **WaitForSingleObject** et regarder le résultat. Si on a **WAIT_TIMEOUT**, l'Event n'est toujours pas passé à "Vrai" sinon ... il est passé à "Vrai".
>
> Je n'ai pas trouvé de meilleure traduction avec les "Vrai" et "Faux". Mais dans la doc Microsoft, c'est "*signaled*" et "*non-signaled*".
> Bref, il y a deux états!
>
> 

On revient au challenge et on passe à la transformation en elle-même :

```c
int transformPass()
{
  HANDLE Thread; // eax
  CHAR Name[30]; // [esp+23h] [ebp-965h] BYREF
  char v3[16]; // [esp+41h] [ebp-947h] BYREF
  char lpThreadId[2323]; // [esp+51h] [ebp-937h] BYREF
  HANDLE hEvent; // [esp+964h] [ebp-24h]
  BOOL v6; // [esp+968h] [ebp-20h]
  HANDLE hHandle; // [esp+96Ch] [ebp-1Ch]
  char v8[4]; // [esp+970h] [ebp-18h]
  LPVOID lpParameter; // [esp+974h] [ebp-14h]
  DWORD nCount; // [esp+978h] [ebp-10h]
  int i; // [esp+97Ch] [ebp-Ch]

  for ( i = 0; ; ++i )
  {
    nCount = 0;
    for ( lpParameter = (i << 6); lpParameter < sub_40190B(576, (i + 1) << 6); lpParameter = lpParameter + 1 )
    {
      ++nCount;
      Thread = CreateThread(0, 0, StartAddress, lpParameter, 0, &lpThreadId[15]);
      *&lpThreadId[4 * lpParameter + 19] = Thread;
      if ( !*&lpThreadId[4 * lpParameter + 19] )
      {
        printf("Can't create thread %d\n", lpParameter);
        return 0;
      }
    }
    WaitForMultipleObjects(nCount, &lpThreadId[256 * i + 19], 1, 0xFFFFFFFF);
    if ( sub_40190B((i + 1) << 6, 576) == 576 )
      break;
  }
  *v8 = 0;
  while ( *v8 <= 575 )
  {
    strcpy(lpThreadId, "Global\\cell_%d");
    strcpy(v3, "Global\\ncell_%d");
    printflike(Name, 0x1Eu, v3, v8[0]);
    hHandle = OpenEventA(0x1F0003u, 0, Name);
    v6 = WaitForSingleObject(hHandle, 0xAu) != 258;
    printflike(Name, 0x1Eu, lpThreadId, v8[0]);
    hEvent = OpenEventA(0x1F0003u, 0, Name);
    if ( v6 )
      SetEvent(hEvent);
    else
      ResetEvent(hEvent);
    ++*v8;
  }
  return 0;
}
```

La première boucle va calculer le prochain état bit à bit par bloc de 64.

Pourquoi 64 ? A priori c'est juste pour éviter de créer d'un coup 576 threads :grimacing:

Chaque calcul sera fait dans un thread. À la fin de la boucle, on attend que chaque thread soit terminé avec **WaitForSingleObject** comme pour les Events.

Ensuite, pour chaque bit, on récupère son état depuis **Global\\ncell_x** et on modifie **Global\\cell_x** en conséquence.

On arrive finalement au calcul des nouveaux bits, la seule partie vraiment utile.

```c
DWORD __stdcall StartAddress(LPVOID lpThreadParameter)
{
  unsigned int v1; // edx
  CHAR Name[30]; // [esp+1Fh] [ebp-69h] BYREF
  char v4[16]; // [esp+3Dh] [ebp-4Bh] BYREF
  char v5[19]; // [esp+4Dh] [ebp-3Bh] BYREF
  int v6; // [esp+60h] [ebp-28h]
  BOOL v7; // [esp+64h] [ebp-24h]
  BOOL v8; // [esp+68h] [ebp-20h]
  BOOL v9; // [esp+6Ch] [ebp-1Ch]
  HANDLE v10; // [esp+70h] [ebp-18h]
  HANDLE v11; // [esp+74h] [ebp-14h]
  HANDLE hHandle; // [esp+78h] [ebp-10h]
  char v13[4]; // [esp+7Ch] [ebp-Ch]

  strcpy(v5, "Global\\cell_%d");
  strcpy(v4, "Global\\ncell_%d");
  *v13 = lpThreadParameter;
  printflike(Name, 0x1Eu, v5, lpThreadParameter);
  hHandle = OpenEventA(0x1F0003u, 0, Name);
  if ( *v13 )
    v1 = (*v13 - 1) % 0x240u;
  else
    LOBYTE(v1) = 63;
  printflike(Name, 0x1Eu, v5, v1);
  v11 = OpenEventA(0x1F0003u, 0, Name);
  printflike(Name, 0x1Eu, v5, (*v13 + 1) % 0x240u);
  v10 = OpenEventA(0x1F0003u, 0, Name);
  v9 = WaitForSingleObject(hHandle, 0xAu) != 258;
  v8 = WaitForSingleObject(v11, 0xAu) != 258;
  v7 = WaitForSingleObject(v10, 0xAu) != 258;
  v6 = v8 ^ (!v9 && !v7);
  v6 = v6 != 0;
  printflike(Name, 0x1Eu, v4, v13[0]);
  *&v5[15] = OpenEventA(0x1F0003u, 0, Name);
  if ( v6 )
    SetEvent(*&v5[15]);
  else
    ResetEvent(*&v5[15]);
  return 0;
}
```

Ca lit les bits depuis **Global\\cell_x**, calcule le prochain bit puis met à jour **Global\\ncell_x**.

Le plus important, c'est cette ligne :

    v6 = v8 ^ (!v9 && !v7);

- **v6** correspond au prochain état du bit courant.

- **v8** correspond au bit précédent. Et si on est au bit 0, cela correspond au dernier bit, le 575.

- **v9** correspond au bit courant.

- **v7** correspond au bit suivant.

Pour résumer, cela donne :

next_bit<sub>x</sub> = bit<sub>x-1</sub> xor (!bit<sub>x</sub> && !bit<sub>x+1</sub>) 

Et c'est tout ce qu'il nous faut !

Le reste, c'est juste de la copie de bits entre Events, ...
D'ailleurs tous ces threads et Events, ça prend du temps. Il faut environ 15 secondes pour tester un mot de passe sur mon PC. Et si on voulait bruteforcer, ça ne pourrait pas marcher car tout les Events sont partagés, lancer plusieurs processus en même temps ne servirait à rien.

Par contre, on pourrait créer plusieurs binaires avec des noms d'Event différents en changeant un caractère ou plus.

Mais comme dans le Python tout est bon ou presque, on passe au Python.

Voilà la transformation:

```python
def transformation(b):
    res = []
    for i in range(576):
        bit_prev = b[(i - 1) % 576 if i != 0 else 575]
        bit_cur = b[i]
        bit_next = b[(i + 1) % 576]
        res.append(bit_prev ^ ((bit_cur == 0) and (bit_next == 0)))
    return res
```

Il y a peut-être un moyen de reverser cette transformation, mais un peu de bruteforce c'est bien aussi 🤠.

## Solution

Pour chaque indice, on teste différents caractères et on regarde combien d'octets à la fin sont bons en comparant avec le
résultat attendu.

Avant de bruteforcer, il faut trouver le dernier caractère du flag.

Comme on prend le bit précédent, le premier octet final dépend aussi du dernier octet du mot de passe.

```python
def find_last_char():
    best = (0, None)
    for c1 in charset:
        s1[-1] = c1
        r = score(test(xor(s1, key)), reference)
        if r >= best[0]:
            best = (r, c1)
    print("Last char is", best[1])  # I
    s1[-1] = best[1]
    print("".join(map(chr, s1)))
```

On trouve que le dernier caractère est **I**.

Maintenant on peut bruteforcer chaque caractère en testant les deux suivants, au cas où on ait besoin du bit du caractère 
suivant.

```python
i = 70
best = [0, set()]
for c1 in charset:
    s1[i] = c1
    for c2 in charset:
        s1[i + 1] = c2
        r = score(test(xor(s1, key)), reference)
        if r > best[0]:
            best = [r, {c1}]
        elif r == best[0]:
            best[1].add(c1)
print("Best char for", i, "is", list(map(chr, best[1])))
```

Cette fonction teste toutes les combinaisons de 2 caractères et garde les meilleurs résultats.

On trouve généralement un ou deux caractères possibles à chaque fois. Mais en testant les suivants, on voit qu'il n'y a, en fin de compte, qu'un seul caractère possible.

Ça prend un peu de temps de faire les 16 caractères qui nous manquent pour l'URL, mais on arrive facilement à la solution !

Il y a surement une solution plus optimisée et ça devrait pouvoir aussi se faire avec des outils comme [**z3**](https://github.com/Z3Prover/z3).

## Remarque

Vu les URLs précédentes, le charset est a priori `[A-Za-z0-9]`.
Mais on ne trouve plus de solution possible au bout d'un moment.

En fait, il faut rajouter `-` au charset. Un petit détail, mais il faut y penser :man_shrugging:.

On peut passer au prochain (et dernier) challenge.

# Challenge 4

Pour celui-là, on a un binaire ARM avec les bibliothèques qu'il faut pour le lancer.

```powershell
PS D:\FIC2021 Chall\ChallengeCERT#4> file .\AT-AT.bin
.\AT-AT.bin: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, BuildID[sha1]=9475d7b94edd198234e7be148c8acaec728987f5, for GNU/Linux 3.2.0, stripped
```

Pour le lancer, on peut utiliser `qemu-arm-static`.

```bash
debian@debian:/mnt/d/FIC2021 Chall/ChallengeCERT#4$ qemu-arm-static ./AT-AT.bin
Welcome to ATATATATATATATAT
Please enter the password to decrypt the secret plans
Password: secretpassword

Invalid password
Decryption failure:
[random chars]
```


Ça lit un mot de passe et déchiffre les plans secrets, peu importe le mot de passe, puis les affiche.

Le binaire n'est pas petit (526 Ko) mais n'a pas l'air d'avoir beaucoup de code :thinking:.

## Machine virtuelle

Voilà le `main` après renommage.

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  char *v3; // r10
  int v4; // r2
  int v5; // r3
  __int64 v6; // [sp-28h] [bp-44h]
  int v7; // [sp-20h] [bp-3Ch]
  int v8; // [sp-1Ch] [bp-38h]
  int instrOffset; // [sp+10h] [bp-Ch]

  instrOffset = 5482;
  printf("Welcome to %s\n", instr);
  mprotect(instr, 0x1000u, 7);
  v6 = 0LL;
  v7 = 0;
  v8 = 0;
  while ( 1 )
  {
    do
      instrOffset = offset(instrOffset);
    while ( check_exists(instrOffset >> 1) );
    usedOffset[usedOffsetIdx++] = instrOffset >> 1;
    decryptInstr(instr, &unk_23000 + 16 * (instrOffset >> 1), HIWORD(instrOffset));
    v3 = instr;
    if ( (instrOffset & 1) != 0 )
      v3 = &instr[1];
    v6 = (v3)(v6, HIDWORD(v6), v7, v8);
    v7 = v4;
    v8 = v5;
    strcpy(instr, src);
  }
}
```

Nous avons une boucle qui va calculer un offset, déchiffrer quelque chose avec les données de *unk_23000* et l'exécuter ... une VM !

## Dump du code

Pour dumper le code de la VM, on peut utiliser `gdb`, mettre un breakpoint à *22000* (v3) et afficher les instructions.

Par exemple, avec le script `gdb` suivant :

```bash
set logging on
b *0x22000
commands
x/2i 0x22000
end
```

Seule la première instruction est vraiment utile, la seconde, c'est presque toujours `bx lr` pour revenir au `main` ou encore la modification du registre `r3`
aprés une comparaison.

Sinon on peut récupérer les instructions en recodant le décodeur avec un script en Python.

Pour les décoder correctement, il faut voir que suivant le dernier bit de l'offset, ça switch en mode [Thumb](https://www.keil.com/support/man/docs/armasm/armasm_dom1359731125707.htm). Mais c'est fait exprès :smirk:

Après, il reste à coder un peu.

```python
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
    tab = set()
    while True:
        while True:
            instr = nextint(instr)
            offset = (instr & 0xffff) >> 1
            if offset not in tab:
                tab.add(offset)
                break

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
```


 On récupère une liste d'environ 2000 instructions.

## Analyse du code

Après analyse, il y a 4 parties dans ce code. On peut les trouver facilement en cherchant où se trouvent les modifications
du registre `r7` qui contrôle le syscall à appeler.

- On écrit le message *"Please enter the password to decrypt the secret plans"* sur Stdout.

    ```assembly
    # Write challenge message
    
    4ff00100		mov.w	r0, #1              # stdout
    0120a0e3		mov	r2, #1              # 1 byte to write
    0470a0e3		mov	r7, #4              # WRITE syscall
    06f15001		add.w	r1, r6, #0x50       # Please enter the password to decrypt the secret plans
    000000ef		svc	#0
    06f16c01		add.w	r1, r6, #0x6c
    00df    		svc	#0
    ...
    ```
    
- On lit le password (42 caractères)

     ```assembly
     # Read 42 chars (password) to r4 = @A3004
     
     0000a0e3		mov	r0, #0
     0410a0e1		mov	r1, r4
     2a20a0e3		mov	r2, #0x2a
     4ff00307		mov.w	r7, #3        # READ syscall
     00df    		svc	#0
     
     # Set last char to '\0'
     
     000020e0		eor	r0, r0, r0
     84f82900		strb.w	r0, [r4, #0x29]
     ```

- Vérification du password.

    Une erreur met un bit de `r3` à 1. À la fin, suivant ce bit, le bon message est affiché ou pas.

    ```assembly
    4ff00100		mov.w	r0, #1
    55f82310		ldr.w	r1, [r5, r3, lsl #2]
    4ff02e02		mov.w	r2, #0x2e
    0470a0e3		mov	r7, #4          # WRITE syscall 
    000000ef		svc	#0
    ```

    Revenons à la vérification.

    Pour chaque test, j'ai mis la signification avant.
    
    - `pdw[x] => password[x:x+4]`
    - `pw[x] => password[x:x+2]`
    - `pb[x] => password[x]`
    
    Le code:
    
    ```assembly
    # pdw[0] == pdw[10]
    2246    		mov	r2, r4
    000092e5		ldr	r0, [r2]
    d2f80a10		ldr.w	r1, [r2, #0xa]
    010050e1		cmp	r0, r1
    01308313		orrne	r3, r3, #1
    
    # pdw[4] == pdw[14]
    02f10402		add.w	r2, r2, #4
    1068    		ldr	r0, [r2]
    0a1092e5		ldr	r1, [r2, #0xa]
    010050e1		cmp	r0, r1
    01308313		orrne	r3, r3, #1
    
    # pw[8] == pw[18]
    02f10402		add.w	r2, r2, #4
    1088    		ldrh	r0, [r2]
    ba10d2e1		ldrh	r1, [r2, #0xa]
    010050e1		cmp	r0, r1
    01308313		orrne	r3, r3, #1
    
    # pdw[28] & unk_21050[20] = unk_21050[12]
    1c0094e5		ldr	r0, [r4, #0x1c]
    d9f81410		ldr.w	r1, [sb, #0x14]
    00ea0100		and.w	r0, r0, r1
    0c2099e5		ldr	r2, [sb, #0xc]
    020050e1		cmp	r0, r2
    01308313		orrne	r3, r3, #1
    
    # ((((pw[5]*2)+pw[5])*2)+pw[5]) = unk_21050[32]
    b4f80500		ldrh.w	r0, [r4, #5]
    0146    		mov	r1, r0
    0944    		add	r1, r1
    001081e0		add	r1, r1, r0
    0944    		add	r1, r1
    001081e0		add	r1, r1, r0
    202099e5		ldr	r2, [sb, #0x20]
    020051e1		cmp	r1, r2
    01308313		orrne	r3, r3, #1
    
    # pb[40] == pb[39]
    282084e2		add	r2, r4, #0x28
    0000d2e5		ldrb	r0, [r2]
    a2f10102		sub.w	r2, r2, #1
    0010d2e5		ldrb	r1, [r2]
    010050e1		cmp	r0, r1
    01308313		orrne	r3, r3, #1
    
    # pb[40] == pb[38]
    012042e2		sub	r2, r2, #1
    0010d2e5		ldrb	r1, [r2]
    010050e1		cmp	r0, r1
    01308313		orrne	r3, r3, #1
    
    # pdw[20]+pdw[24] = unk_21050[16]
    6069    		ldr	r0, [r4, #0x14]
    181094e5		ldr	r1, [r4, #0x18]
    010080e0		add	r0, r0, r1
    102099e5		ldr	r2, [sb, #0x10]
    020050e1		cmp	r0, r2
    01308313		orrne	r3, r3, #1
    
    # pdw[7] xor 0xffffffff = unk_21050[8]
    d700c4e1		ldrd	r0, r1, [r4, #7]
    0020a0e3		mov	r2, #0
    012042e2		sub	r2, r2, #1
    80ea0200		eor.w	r0, r0, r2
    021021e0		eor	r1, r1, r2
    082099e5		ldr	r2, [sb, #8]
    020050e1		cmp	r0, r2
    01308313		orrne	r3, r3, #1
    
    # pdw[11] xor 0xffffffff = unk_21050[0]
    d9f80020		ldr.w	r2, [sb]
    020051e1		cmp	r1, r2
    01308313		orrne	r3, r3, #1
    
    # pb[32] == pb[31]+36
    1f2084e2		add	r2, r4, #0x1f
    1178    		ldrb	r1, [r2]
    01f12401		add.w	r1, r1, #0x24
    02f10102		add.w	r2, r2, #1
    1078    		ldrb	r0, [r2]
    010040e0		sub	r0, r0, r1
    003083e1		orr	r3, r3, r0
    
    # pb[33] == pb[31]+36+10
    0a1081e2		add	r1, r1, #0xa
    012082e2		add	r2, r2, #1
    0000d2e5		ldrb	r0, [r2]
    010040e0		sub	r0, r0, r1
    003083e1		orr	r3, r3, r0
    
    # pb[34] == pb[31]+36+10-59
    a1f13b01		sub.w	r1, r1, #0x3b
    02f10102		add.w	r2, r2, #1
    0000d2e5		ldrb	r0, [r2]
    010040e0		sub	r0, r0, r1
    43ea0003		orr.w	r3, r3, r0
    
    # pb[35] == pb[31]+36+10-59+32
    01f12001		add.w	r1, r1, #0x20
    02f10102		add.w	r2, r2, #1
    0000d2e5		ldrb	r0, [r2]
    a0eb0100		sub.w	r0, r0, r1
    43ea0003		orr.w	r3, r3, r0
    
    # pb[36] == pb[31]+36+10-59+32-30
    1e1041e2		sub	r1, r1, #0x1e
    012082e2		add	r2, r2, #1
    0000d2e5		ldrb	r0, [r2]
    010040e0		sub	r0, r0, r1
    003083e1		orr	r3, r3, r0
    
    # pb[37] == pb[31]+36+10-59+32-30+42
    01f12a01		add.w	r1, r1, #0x2a
    012082e2		add	r2, r2, #1
    0000d2e5		ldrb	r0, [r2]
    010040e0		sub	r0, r0, r1
    003083e1		orr	r3, r3, r0
    
    # pb[38] == pb[31]+36+10-59+32-30+42-62
    a1f13e01		sub.w	r1, r1, #0x3e
    012082e2		add	r2, r2, #1
    0000d2e5		ldrb	r0, [r2]
    a0eb0100		sub.w	r0, r0, r1
    003083e1		orr	r3, r3, r0
    
    # Set r3 to 1 if last tests failed
    4ff00000		mov.w	r0, #0
    000053e1		cmp	r3, r0
    0130a013		movne	r3, #1
    
    # pdw[28] & unk_21050[4] == unk_21050[24]
    e069    		ldr	r0, [r4, #0x1c]
    041099e5		ldr	r1, [sb, #4]
    010000e0		and	r0, r0, r1
    d9f81820		ldr.w	r2, [sb, #0x18]
    020050e1		cmp	r0, r2
    01308313		orrne	r3, r3, #1
    
    # pdw[24] ror 11 == unk_21050[28]
    180094e5		ldr	r0, [r4, #0x18]
    e005a0e1		ror	r0, r0, #0xb
    d9f81c10		ldr.w	r1, [sb, #0x1c]
    010050e1		cmp	r0, r1
    01308313		orrne	r3, r3, #1
    ```

À partir de ces contraintes, on pourrait utiliser **[z3](https://github.com/Z3Prover/z3)** et autres, ou faire ça en codant un peu !

## Solution

Chaque test nous donne une partie du flag moyennant un peu de C et de bruteforce pour quelques octets, on arrive à la solution assez vite.

  ```c
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
  ```


On obtient finalement le plan secret qui me rappelle quelque chose :thinking:.

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

Ainsi qu'un lien vers la partie 5.





# Challenge 5

Cette partie n'est pas un autre challenge, mais juste les instructions pour prévenir Naval Group qu'on a fini le challenge.
