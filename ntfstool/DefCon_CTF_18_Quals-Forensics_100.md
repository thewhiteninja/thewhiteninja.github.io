# DefCon CTF 18 Quals

## Forensics 100

### Description

    Find the key, and they gave us the following file which revealed to be a gzipped raw disk image.
	
### Files

- [f100_6db079ca91c4860f.zip](files/f100_6db079ca91c4860f.zip)

### Solution

Let's find the key!

1. A file named f100_6db079ca91c4860f.bin?

   We can get info about the image using [info](https://github.com/thewhiteninja/ntfstool#info) command.
   It works for disk images but also volume images.

   ```
   > .\ntfstool.x64.exe info image=d:\f100_6db079ca91c4860f.bin
   Info for image: d:\f100_6db079ca91c4860f.bin
   --------------------------------------------
   
   Creation    : 2022-04-10 20:57:23
   Modification: 2010-05-22 01:48:34
   Access      : 2022-04-10 21:35:55
   
   Hash SHA256 [y/N] ? N
   
   Size        : 16187392 (15.44 MiBs)
   Volume      : MBR
   
   +---------------------------------------------------------------------------+
   | Id | Boot | Filesystem | Offset           | Size                          |
   +---------------------------------------------------------------------------+
   | 0  | No   | NTFS       | 0000000000003e00 | 0000000000f68c00 (15.41 MiBs) |
   +---------------------------------------------------------------------------+
   ```
   
   Only one NTFS volume.
   
2. What about this volume?

   We can add the `volume` option to get more information about the volume using the [info](https://github.com/thewhiteninja/ntfstool#info) command.

   ```
   .\ntfstool.x64.exe info image=d:\f100_6db079ca91c4860f.bin volume=0
   Info for image: d:\f100_6db079ca91c4860f.bin > Volume:0
   -------------------------------------------------------
   
   Filesystem     : NTFS
   Bootable       : False
   Offset         : 15872 (15.50 KiBs)
   Size           : 16157696 (15.41 MiBs)
   Bitlocker      : False
   ```


3. Where is the key?

   As the file is relatively small, we can dump and analyze it into a CSV file using [mft.dump](https://github.com/thewhiteninja/ntfstool#mft-dump) command.
   
   ```
   > .\ntfstool.x64.exe mft.dump image=d:\f100_6db079ca91c4860f.bin volume=0 format=csv output=d:\mft.csv
   MFT Dump (inode:0) for d:\f100_6db079ca91c4860f.bin > Volume:0
   --------------------------------------------------------------
   
   [+] $MFT size   : 256.00 KiBs
   [-] Record size : 1024
   [-] Record count: 256
   [+] Creating d:\mft.csv
   [+] Processing data: 256.00 KiBs
   [+] Closing volume
   ```
   
   You can download the CSV file here: [mft.csv](files/mft.csv)
   
4. Read the CSV

   [Tad](https://www.tadviewer.com/) is a CSV file viewer with a nice select feature as the SQL select.
   
   Here is the result.
   
   ![mft.csv](https://github.com/thewhiteninja/thewhiteninja.github.io/blob/main/ntfstool/images/mft.csv.png?raw=true "mft.csv with Tad")
   
   We have one deleted file (inode: 38) named "key".
   
   And it is suspicious as the size of the data is 0.
   
5. Check the file record

   We can print the file record for this file using the [mft.record](https://github.com/thewhiteninja/ntfstool#mft-record) command.
   
   ```
   > .\ntfstool.x64.exe mft.record image=d:\f100_6db079ca91c4860f.bin volume=0 inode=38
   MFT (inode:38) for d:\f100_6db079ca91c4860f.bin > Volume:0
   ----------------------------------------------------------
   
   Signature         : FILE
   Update Offset     : 48
   Update Number     : 3
   $LogFile LSN      : 1072197
   Sequence Number   : 2
   Hardlink Count    : 1
   Attribute Offset  : 56
   Flags             : Not in use
   Real Size         : 416
   Allocated Size    : 1024
   Base File Record  : 0000000000000000h
   Next Attribute ID : 4
   MFT Record Index  : 38
   Update Seq Number : 10
   Update Seq Array  : 00000000
   
   Attributes:
   -----------
   
   +---------------------------------------------------------------------------------------------------------+
   | Id | Type                       | Non-resident | Length | Overview                                      |
   +---------------------------------------------------------------------------------------------------------+
   | 1  | $STANDARD_INFORMATION      | False        | 72     | File Created Time       : 2010-05-19 00:45:50 |
   |    | Raw address: 00000052f650h |              |        | Last File Write Time    : 2010-05-19 02:31:59 |
   |    |                            |              |        | FileRecord Changed Time : 2010-05-19 02:31:59 |
   |    |                            |              |        | Last Access Time        : 2010-05-19 00:45:50 |
   |    |                            |              |        | Permissions             :                     |
   |    |                            |              |        |   read_only     : 0                           |
   |    |                            |              |        |   hidden        : 0                           |
   |    |                            |              |        |   system        : 0                           |
   |    |                            |              |        |   device        : 0                           |
   |    |                            |              |        |   normal        : 0                           |
   |    |                            |              |        |   temporary     : 0                           |
   |    |                            |              |        |   sparse        : 0                           |
   |    |                            |              |        |   reparse_point : 0                           |
   |    |                            |              |        |   compressed    : 0                           |
   |    |                            |              |        |   offline       : 0                           |
   |    |                            |              |        |   not_indexed   : 0                           |
   |    |                            |              |        |   encrypted     : 0                           |
   |    |                            |              |        | Max Number of Versions  : 0                   |
   |    |                            |              |        | Version Number          : 0                   |
   +---------------------------------------------------------------------------------------------------------+
   | 2  | $FILE_NAME                 | False        | 72     | Parent Dir Record Index : 5                   |
   |    | Raw address: 00000052f6b0h |              |        | Parent Dir Sequence Num : 5                   |
   |    |                            |              |        | File Created Time       : 2010-05-19 02:31:59 |
   |    |                            |              |        | Last File Write Time    : 2010-05-19 02:31:59 |
   |    |                            |              |        | FileRecord Changed Time : 2010-05-19 02:31:59 |
   |    |                            |              |        | Last Access Time        : 2010-05-19 02:31:59 |
   |    |                            |              |        | Allocated Size          : 0                   |
   |    |                            |              |        | Real Size               : 0                   |
   |    |                            |              |        | ------                                        |
   |    |                            |              |        | NameType                : DOS & WIN32         |
   |    |                            |              |        | Name                    : key                 |
   +---------------------------------------------------------------------------------------------------------+
   | 3  | $DATA                      | False        | 0      | Size: 0 (0.00 byte)                           |
   |    | Raw address: 00000052f710h |              |        |                                               |
   +---------------------------------------------------------------------------------------------------------+
   | 4  | $DATA                      | False        | 26     | Name: Zone.Identifier                         |
   |    | Raw address: 00000052f778h |              |        | Size: 26 (26.00 bytes)                        |
   +---------------------------------------------------------------------------------------------------------+
   ```
   
   There are two streams for this file.
   
   - The actual data is in a resident attribute (everything is in the file record). But the size is 0.   
   - There is also a `Zone.Identifier` ADS. This file has probably been downloaded from Internet.
   
   
6. Extract the "Zone.Identifier" file content

   With the [extract](https://github.com/thewhiteninja/ntfstool#extract) command, we can ... extract the content of a file from the inode or path.
   
   There is a `stream` to select the alternate data stream.
   
   ```
   > .\ntfstool.x64.exe extract image=d:\f100_6db079ca91c4860f.bin volume=0 inode=38 stream=Zone.Identifier output=d:\Zone.txt
   Extract file for d:\f100_6db079ca91c4860f.bin > Volume:0
   --------------------------------------------------------
   
   [+] Opening d:\f100_6db079ca91c4860f.bin
   [-] Record Num  : 38 (00000026h)
   [-] Stream      : Zone.Identifier
   [-] Destination : d:\Zone.txt
   [+] Extracting file...
   [+] 26 bytes (26.00 bytes) written
   ```

   ```   
   > cat D:\Zone.txt
   [ZoneTransfer]
   ZoneId=3
   ```
   
   Ok, nothing interesting in the file.
   
7. So, where is the key?

   A size of 0 doesn't mean that there is no data :smirk:
   
   There is actually some space in the attribute data.

   We cannot extract the content as the ntfstool will follow the size in the record.
   
   But, using the raw offset, we can open the file in a hex editor and check the content.
   
   ```
   +---------------------------------------------------------------------------------------------------------+
   | 3  | $DATA                      | False        | 0      | Size: 0 (0.00 byte)                           |
   |    | Raw address: 00000052f710h |              |        |                                               |
   +---------------------------------------------------------------------------------------------------------+
   ```
   
   Let's see the file at offset: 0x52f710
   
8. HexEdit

   ![hexedit.png](https://github.com/thewhiteninja/thewhiteninja.github.io/blob/main/ntfstool/images/hexedit.png?raw=true "File at 0x52f710")
   
9. EOC (End of chall)
