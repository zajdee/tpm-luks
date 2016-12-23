#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <errno.h>
#include <sha1.h> // apt install libmd0 libmd-dev

#include <efi.h>
#include <efilib.h>
#include <linux/uuid.h>
#include "include/efistruct.h"
#include "include/PeImage.h"
#include "include/UefiGpt.h"
#include "include/UefiTcgPlatform.h"


///
/// http://ftp.icm.edu.pl/packages/Hacked%20Team.git/vector-edk/SecurityPkg/Library/DxeTpmMeasureBootLib/DxeTpmMeasureBootLib.c
///

//
// Flag to check GPT partition. It only need be measured once.
//
BOOLEAN                           mMeasureGptTableFlag = FALSE;
EFI_GUID                          mZeroGuid = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};
UINTN                             mMeasureGptCount = 0;
VOID                              *mFileBuffer;
UINTN                             mImageSize;
//
// Measured FV handle cache
//
EFI_HANDLE                        mCacheMeasuredHandle  = NULL;


VOID *LoadFileIntoBuffer(char *filename, long int *bufferSize)
{
        long unsigned int size, read;
        FILE *fp;
        VOID *buff;

        *bufferSize = 0;

        fp = fopen(filename, "r");
        if (fp  == NULL) {
                fprintf(stderr, "File not found.\n");
                return NULL;
        }
        fseek(fp, 0L, SEEK_END);
        size = ftell(fp);
        fprintf(stderr, "File has size %lu bytes.\n", size);
        fseek(fp, 0L, SEEK_SET);
        if (size == 0) {
                fclose(fp);
                return NULL;
        }
        buff = calloc(1, size);
        if (buff == NULL) {
                fprintf(stderr, "Cannot allocate memory to load file.\n");
                fclose(fp);
                return NULL;
        }
        read = fread(buff, 1, size, fp);
        if (read != size) {
                fprintf(stderr, "Expected %lu bytes, read %lu bytes. Bailing out.\n", size, read);
                fclose(fp);
                free(buff);
                return NULL;
        }
        fclose(fp);
        *bufferSize = size;
        return buff;
}

VOID *LoadFilePartIntoBuffer(char *filename, long int *bufferSize, unsigned long int fileStart, unsigned long int dataSize)
{
        long unsigned int read;
        FILE *fp;
        VOID *buff;

        *bufferSize = 0;

        fp = fopen(filename, "r");
        if (fp  == NULL) {
                fprintf(stderr, "File not found.\n");
                return NULL;
        }
        fseek(fp, fileStart, SEEK_SET);
        buff = calloc(1, dataSize);
        if (buff == NULL) {
                fprintf(stderr, "Cannot allocate memory to load file.\n");
                fclose(fp);
                return NULL;
        }
        read = fread(buff, 1, dataSize, fp);
        if (read != dataSize) {
                fprintf(stderr, "Expected %lu bytes, read %lu bytes. Bailing out.\n", dataSize, read);
                fclose(fp);
                free(buff);
                return NULL;
        }
        fclose(fp);
        *bufferSize = dataSize;
        return buff;
}

int CalculateMBRHash(char *filename, unsigned long int fileStart, unsigned long int dataSize)
{
        UINT8 *ImageAddress;
        SHA1_CTX Sha1Ctx;
        long int bufferSize = 0;
        uint8_t results[SHA1_DIGEST_LENGTH];
        int n = 0;

        // shall there be no filename on input, then return
        if (filename == NULL)
                return 1;
        ImageAddress = LoadFilePartIntoBuffer(filename, &bufferSize, fileStart, dataSize); // we measure bytes 0x0 to 0x1B8
        if (ImageAddress == NULL) return 2;

        fprintf(stderr, "Measuring %lu bytes of MBR from start %lu...\n", dataSize, fileStart);
        SHA1Init(&Sha1Ctx);
        SHA1Update(&Sha1Ctx, (uint8_t *)ImageAddress, bufferSize);
        SHA1Final(results, &Sha1Ctx);

        for (n = 0; n < SHA1_DIGEST_LENGTH; n++)
                printf("%02x", results[n]);
        putchar('\n');
        free(ImageAddress);
        return 0;
}

int CalculateMBRIPLHash(char *filename)
{
        return CalculateMBRHash(filename, 0, 440);
}

int CalculateMBRDataHash(char *filename)
{
        return CalculateMBRHash(filename, 440, 72);
}

int CalculateGrubStage15Hash(char *filename)
{
// assume block size 512 bytes
// read 1 sector (determine sector LBA from MBR)
// dd if=/dev/sda of=diskboot.img bs=512 skip=$(dd status=none if=/dev/sda bs=1c skip=92 count=4 | hexdump -v -e '7/4 "%d "' -e '"\n"' /dev/stdin) count=1
        long unsigned int read, dataSize;
        FILE *fp;
        UINT64 stage15LBA;
        UINT8 stage15[512];
        SHA1_CTX Sha1Ctx;
        uint8_t results[SHA1_DIGEST_LENGTH];
        int n = 0;

        fp = fopen(filename, "r");
        if (fp  == NULL) {
                fprintf(stderr, "File not found.\n");
                return 1;
        }
        // 92 = 0x5c = GRUB_BOOT_MACHINE_KERNEL_SECTOR = this is where GRUB stage1.5 LBA sector lies
        fseek(fp, 92, SEEK_SET);
        dataSize = sizeof(stage15LBA); // XXX: FIXUP - 8 bytes (UINT64)
        read = fread(&stage15LBA, 1, dataSize, fp);
        if (read != dataSize) {
                fprintf(stderr, "Expected %lu bytes, read %lu bytes. Bailing out.\n", dataSize, read);
                fclose(fp);
                return 2;
        }
        dataSize = 512; // GRUB stage1.5 size = 1 sector
        fseek(fp, stage15LBA * 512, SEEK_SET); // this is where GRUB stage1.5 LBA sector lies
        read = fread(&stage15, 1, dataSize, fp);
        if (read != dataSize) {
                fprintf(stderr, "Expected %lu bytes, read %lu bytes. Bailing out.\n", dataSize, read);
                fclose(fp);
                return 2;
        }
        SHA1Init(&Sha1Ctx);
        SHA1Update(&Sha1Ctx, (uint8_t *)&stage15, dataSize);
        SHA1Final(results, &Sha1Ctx);

        for (n = 0; n < SHA1_DIGEST_LENGTH; n++)
                printf("%02x", results[n]);
        putchar('\n');
        
        fclose(fp);
        return 0;
}
int CalculateGrubStage2Hash(char *filename, int hpWorkaround)
{
// assume block size 512 bytes
// read position (from stage1, offset=500 count=4) and offset (from stage1, offset=508, count=2)
// ## HP workaround: add +1 to count, then cut 511 bytes from the end of resulting file, then sha1sum
// dd if=/dev/sda of=core.img bs=512 skip=$(dd status=none if=diskboot.img bs=1c skip=500 count=4 | hexdump -v -e '7/4 "%d "' -e '"\n"' /dev/stdin) count=$(dd status=none if=diskboot.img bs=1c skip=508 count=2 | hexdump -v -e '7/4 "%d "' -e '"\n"' /dev/stdin)

        long unsigned int read, dataSize;
        FILE *fp;
        UINT64 stage15LBA;
        UINT8 *stage2;
        UINT64 stage2LBA;
        UINT16 stage2count;
        SHA1_CTX Sha1Ctx;
        uint8_t results[SHA1_DIGEST_LENGTH];
        int n = 0;

        fp = fopen(filename, "r");
        if (fp  == NULL) {
                fprintf(stderr, "File not found.\n");
                return 1;
        }
        // 92 = 0x5c = GRUB_BOOT_MACHINE_KERNEL_SECTOR = this is where GRUB stage1.5 LBA sector lies
        fseek(fp, 92, SEEK_SET); // 92 = this is where GRUB stage1.5 LBA sector lies
        dataSize = sizeof(stage15LBA);
        read = fread(&stage15LBA, 1, dataSize, fp);
        if (read != dataSize) {
                fprintf(stderr, "Expected %lu bytes, read %lu bytes. Bailing out.\n", dataSize, read);
                fclose(fp);
                return 2;
        }
        dataSize = sizeof(stage2LBA); // GRUB stage1.5 size = 1 sector
        fseek(fp, stage15LBA * 512 + 500, SEEK_SET); // this is where GRUB stage1.5 LBA sector lies
        read = fread(&stage2LBA, 1, dataSize, fp);
        if (read != dataSize) {
                fprintf(stderr, "Expected %lu bytes, read %lu bytes. Bailing out.\n", dataSize, read);
                fclose(fp);
                return 2;
        }
        dataSize = 2; // GRUB stage1.5 size = 1 sector
        fseek(fp, stage15LBA * 512 + 508, SEEK_SET); // this is where GRUB stage1.5 LBA sector lies
        read = fread(&stage2count, 1, dataSize, fp);
        if (read != dataSize) {
                fprintf(stderr, "Expected %lu bytes, read %lu bytes. Bailing out.\n", dataSize, read);
                fclose(fp);
                return 2;
        }
        fprintf(stderr, "reading stage2, LBA=%lu, sectorCount=%d\n", stage2LBA, stage2count);
        // XXX: HP WORKAROUND is missing here!
        dataSize = stage2count * 512;
        stage2 = calloc(1, dataSize);
        fseek(fp, stage2LBA * 512, SEEK_SET); // this is where GRUB stage1.5 LBA sector lies
        read = fread(stage2, 1, dataSize, fp);
        if (read != dataSize) {
                fprintf(stderr, "Expected %lu bytes, read %lu bytes. Bailing out.\n", dataSize, read);
                fclose(fp);
                return 2;
        }
        fprintf(stderr, "Calculating SHA1...\n");

        SHA1Init(&Sha1Ctx);
        SHA1Update(&Sha1Ctx, (uint8_t *)stage2, dataSize);
        SHA1Final(results, &Sha1Ctx);

        for (n = 0; n < SHA1_DIGEST_LENGTH; n++)
                printf("%02x", results[n]);
        putchar('\n');
        
        fclose(fp);
        return 0;
}

int GetDeviceBlockSize(char *filename)
{
        int fp;
        unsigned int block_size = 0;

        fp = open(filename, O_RDONLY);
        if (fp  <= 0) {
                fprintf(stderr, "File not found.\n");
                return -1;
        }
        // we use BLKSSZGET to get LOGICAL size as this is what everyone in GPT world uses (usually 512 bytes)
        // on Advanced Format disks, BLKSSZGET returns 512B while BLKPBSZGET returns full 4k
        if (0 != ioctl(fp, BLKSSZGET, &block_size)) {
                fprintf(stderr, "ioctl() failed.\n");
                return -1;
        }
        close(fp);
        return block_size;
}

int CompareGuids(EFI_GUID *guid1, EFI_GUID *guid2)
{
        unsigned int diff = 0, i;
        // sanity check
        if ((guid1 == NULL)||(guid2 == NULL)) return -1;
        // does Data4 differ?
        for (i = 0; i < sizeof(guid1->Data4[0]); i++) {
                if (guid1->Data4[i] != guid2->Data4[i]) {
                        diff = 1;
                }
        }

        return (guid1->Data1 == guid2->Data1)&&(guid1->Data2 == guid2->Data2)&&(guid1->Data3 == guid2->Data3)&&!diff;
}

int CalculateGPTHash(char *filename)
{
  EFI_PARTITION_TABLE_HEADER        *PrimaryHeader;
  EFI_PARTITION_ENTRY               *PartitionEntry;
  UINT8                             *EntryPtr;
  UINTN                             NumberOfPartition;
  UINT32                            Index;
  EFI_GPT_DATA                      *GptData;
  UINT32                            EventSize;

  SHA1_CTX Sha1Ctx;
  long int bufferSize = 0;
  uint8_t results[SHA1_DIGEST_LENGTH];
  int n = 0;
  int blockSize = 0;

  // shall there be no filename on input, then return
  if (filename == NULL)
     return 1;

  blockSize = GetDeviceBlockSize(filename);
  if (blockSize <= 0) return 4;

  fprintf(stderr, "Device block size = %d\n", blockSize);

  // GPT is on LBA 1, therefore we read start = 1 * blockSize, length = blockSize
  // now we read GPT

  PrimaryHeader = (EFI_PARTITION_TABLE_HEADER *)LoadFilePartIntoBuffer(filename, &bufferSize, 1 * blockSize, blockSize); // we measure bytes 0x0 to 0x1B8
  if (PrimaryHeader == NULL) return 4;

  if (PrimaryHeader->Header.Signature != 0x5452415020494645) { // hex bytes: 45 46 49 20 50 41 52 54, "EF PART"
        free(PrimaryHeader);
        fprintf(stderr, "No valid GPT header found.\n");
        return 3;
  }

  fprintf(stderr, "NumberOfEntries=%d, SizeOfPartitionEntry=%d, PartitionEntryLBA=%lu\n", PrimaryHeader->NumberOfPartitionEntries, PrimaryHeader->SizeOfPartitionEntry,
        PrimaryHeader->PartitionEntryLBA);

  EntryPtr = (UINT8 *)LoadFilePartIntoBuffer(filename, &bufferSize, PrimaryHeader->PartitionEntryLBA * blockSize,
        PrimaryHeader->NumberOfPartitionEntries * PrimaryHeader->SizeOfPartitionEntry);

  PartitionEntry    = (EFI_PARTITION_ENTRY *)EntryPtr;
  NumberOfPartition = 0;
  for (Index = 0; Index < PrimaryHeader->NumberOfPartitionEntries; Index++) {
    if (!CompareGuids (&PartitionEntry->PartitionTypeGUID, &mZeroGuid)) {
      NumberOfPartition++;  
    }
    PartitionEntry = (EFI_PARTITION_ENTRY *)((UINT8 *)PartitionEntry + PrimaryHeader->SizeOfPartitionEntry);
  }
  fprintf(stderr, "NumberOfPartition=%lu\n", NumberOfPartition);

  //
  // Prepare Data for Measurement
  // 
  EventSize = (UINT32)(sizeof (EFI_GPT_DATA) - sizeof (GptData->Partitions) 
                        + NumberOfPartition * PrimaryHeader->SizeOfPartitionEntry);
  GptData = (EFI_GPT_DATA *) calloc(1, EventSize); // + sizeof (TCG_PCR_EVENT_HDR));

  //
  // Copy the EFI_PARTITION_TABLE_HEADER and NumberOfPartition
  //  
  memcpy((UINT8 *)GptData, (UINT8*)PrimaryHeader, sizeof (EFI_PARTITION_TABLE_HEADER));
  GptData->NumberOfPartitions = NumberOfPartition;
  //
  // Copy the valid partition entry
  //
  PartitionEntry    = (EFI_PARTITION_ENTRY*)EntryPtr;
  NumberOfPartition = 0;
  for (Index = 0; Index < PrimaryHeader->NumberOfPartitionEntries; Index++) {
    if (!CompareGuids (&PartitionEntry->PartitionTypeGUID, &mZeroGuid)) {
      memcpy (
        (UINT8 *)&GptData->Partitions + NumberOfPartition * PrimaryHeader->SizeOfPartitionEntry,
        (UINT8 *)PartitionEntry,
        PrimaryHeader->SizeOfPartitionEntry
        );
      NumberOfPartition++;
    }
    PartitionEntry =(EFI_PARTITION_ENTRY *)((UINT8 *)PartitionEntry + PrimaryHeader->SizeOfPartitionEntry);
  }

  // sha1sum over GptData (size TcgEvent->EventSize)
  SHA1Init(&Sha1Ctx);
        fprintf(stderr, "TcgEventSize=%d\n", EventSize);
  SHA1Update(&Sha1Ctx, (uint8_t *)GptData, EventSize);
  SHA1Final(results, &Sha1Ctx);

  for (n = 0; n < SHA1_DIGEST_LENGTH; n++)
     printf("%02x", results[n]);
  putchar('\n');

  free(PrimaryHeader);
  free(EntryPtr);
  return 0;
}

int CalculatePEHash(char *filename)
{
        UINT8 *ImageAddress;
        SHA1_CTX Sha1Ctx;
        long int bufferSize = 0;
        uint8_t results[SHA1_DIGEST_LENGTH];
        int n = 0;

        EFI_STATUS                           Status;
        EFI_IMAGE_DOS_HEADER                 *DosHdr;
        UINT32                               PeCoffHeaderOffset;
        EFI_IMAGE_SECTION_HEADER             *Section;
        UINT8                                *HashBase;
        UINTN                                HashSize;
        UINTN                                SumOfBytesHashed;
        EFI_IMAGE_SECTION_HEADER             *SectionHeader;
        UINTN                                Index;
        UINTN                                Pos;
        UINT16                               Magic;
        EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr;
        UINT32                               NumberOfRvaAndSizes;
        UINT32                               CertSize;
        UINTN                     ImageSize;

        Status        = EFI_UNSUPPORTED;

        // shall there be no filename on input, then return
        if (filename == NULL)
                return 1;

        fprintf(stderr, "Loading file %s\n", filename);

        ImageAddress = LoadFileIntoBuffer(filename, &bufferSize);
        if (ImageAddress == NULL) return 4;

        ImageSize = bufferSize;

        // we have our file loaded at *ImageAddress
        SHA1Init(&Sha1Ctx);
        /// SHA1Update(&sha, (uint8_t *)ImageAddress, bufferSize);
        /// SHA1Final(results, &sha);
  //
  // Check PE/COFF image
  //
  DosHdr = (EFI_IMAGE_DOS_HEADER *) (UINTN) ImageAddress;
  PeCoffHeaderOffset = 0;
  if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    PeCoffHeaderOffset = DosHdr->e_lfanew;
  }

  Hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)((UINT8 *) (UINTN) ImageAddress + PeCoffHeaderOffset);
  if (Hdr.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    goto Finish;
  }

  //
  // Measuring PE/COFF Image Header;
  // But CheckSum field and SECURITY data directory (certificate) are excluded
  //
  if (Hdr.Pe32->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64 && Hdr.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // NOTE: Some versions of Linux ELILO for Itanium have an incorrect magic value 
    //       in the PE/COFF Header. If the MachineType is Itanium(IA64) and the 
    //       Magic value in the OptionalHeader is EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC
    //       then override the magic value to EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC
    //
    Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  } else {
    //
    // Get the magic value from the PE/COFF Optional Header
    //
    Magic = Hdr.Pe32->OptionalHeader.Magic;
  }
  //
  // 3.  Calculate the distance from the base of the image header to the image checksum address.
  // 4.  Hash the image header from its base to beginning of the image checksum.
  //
  HashBase = (UINT8 *) (UINTN) ImageAddress;
  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset
    //
    NumberOfRvaAndSizes = Hdr.Pe32->OptionalHeader.NumberOfRvaAndSizes;
    HashSize = (UINTN) ((UINT8 *)(&Hdr.Pe32->OptionalHeader.CheckSum) - HashBase);
  } else {
    //
    // Use PE32+ offset
    //
    NumberOfRvaAndSizes = Hdr.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
    HashSize = (UINTN) ((UINT8 *)(&Hdr.Pe32Plus->OptionalHeader.CheckSum) - HashBase);
  }

  SHA1Update (&Sha1Ctx, HashBase, HashSize);

  //
  // 5.  Skip over the image checksum (it occupies a single ULONG).
  //
  if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
    //
    // 6.  Since there is no Cert Directory in optional header, hash everything
    //     from the end of the checksum to the end of image header.
    //
    if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset.
      //
      HashBase = (UINT8 *) &Hdr.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - (UINTN) (HashBase - ImageAddress);
    } else {
      //
      // Use PE32+ offset.
      //
      HashBase = (UINT8 *) &Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - (UINTN) (HashBase - ImageAddress);
    }

    if (HashSize != 0) {
      SHA1Update (&Sha1Ctx, HashBase, HashSize);
    }    
  } else {
    //
    // 7.  Hash everything from the end of the checksum to the start of the Cert Directory.
    //
    if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      HashBase = (UINT8 *) &Hdr.Pe32->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN) ((UINT8 *)(&Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - HashBase);
    } else {
      //
      // Use PE32+ offset
      //    
      HashBase = (UINT8 *) &Hdr.Pe32Plus->OptionalHeader.CheckSum + sizeof (UINT32);
      HashSize = (UINTN) ((UINT8 *)(&Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY]) - HashBase);
    }

    if (HashSize != 0) {
      SHA1Update (&Sha1Ctx, HashBase, HashSize);
    }

    //
    // 8.  Skip over the Cert Directory. (It is sizeof(IMAGE_DATA_DIRECTORY) bytes.)
    // 9.  Hash everything from the end of the Cert Directory to the end of image header.
    //
    if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      //
      // Use PE32 offset
      //
      HashBase = (UINT8 *) &Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = Hdr.Pe32->OptionalHeader.SizeOfHeaders - (UINTN) (HashBase - ImageAddress);
    } else {
      //
      // Use PE32+ offset
      //
      HashBase = (UINT8 *) &Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY + 1];
      HashSize = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders - (UINTN) (HashBase - ImageAddress);
    }
    
    if (HashSize != 0) {
      SHA1Update (&Sha1Ctx, HashBase, HashSize);
    }
  }

  //
  // 10. Set the SUM_OF_BYTES_HASHED to the size of the header
  //
  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use PE32 offset
    //
    SumOfBytesHashed = Hdr.Pe32->OptionalHeader.SizeOfHeaders;
  } else {
    //
    // Use PE32+ offset
    //
    SumOfBytesHashed = Hdr.Pe32Plus->OptionalHeader.SizeOfHeaders;
  }
/// ---
  //
  // 11. Build a temporary table of pointers to all the IMAGE_SECTION_HEADER
  //     structures in the image. The 'NumberOfSections' field of the image
  //     header indicates how big the table should be. Do not include any
  //     IMAGE_SECTION_HEADERs in the table whose 'SizeOfRawData' field is zero.
  //
  SectionHeader = (EFI_IMAGE_SECTION_HEADER *) calloc (1, sizeof (EFI_IMAGE_SECTION_HEADER) * Hdr.Pe32->FileHeader.NumberOfSections);
  if (SectionHeader == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Finish;
  }

  //
  // 12.  Using the 'PointerToRawData' in the referenced section headers as
  //      a key, arrange the elements in the table in ascending order. In other
  //      words, sort the section headers according to the disk-file offset of
  //      the section.
  //
  Section = (EFI_IMAGE_SECTION_HEADER *) (
               (UINT8 *) (UINTN) ImageAddress +
               PeCoffHeaderOffset +
               sizeof(UINT32) +
               sizeof(EFI_IMAGE_FILE_HEADER) +
               Hdr.Pe32->FileHeader.SizeOfOptionalHeader
               );
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Pos = Index;
    while ((Pos > 0) && (Section->PointerToRawData < SectionHeader[Pos - 1].PointerToRawData)) {
      memcpy(&SectionHeader[Pos], &SectionHeader[Pos - 1], sizeof(EFI_IMAGE_SECTION_HEADER));
      Pos--;
    }
    memcpy(&SectionHeader[Pos], Section, sizeof(EFI_IMAGE_SECTION_HEADER));
    Section += 1;
  }

  //
  // 13.  Walk through the sorted table, bring the corresponding section
  //      into memory, and hash the entire section (using the 'SizeOfRawData'
  //      field in the section header to determine the amount of data to hash).
  // 14.  Add the section's 'SizeOfRawData' to SUM_OF_BYTES_HASHED .
  // 15.  Repeat steps 13 and 14 for all the sections in the sorted table.
  //
  for (Index = 0; Index < Hdr.Pe32->FileHeader.NumberOfSections; Index++) {
    Section  = (EFI_IMAGE_SECTION_HEADER *) &SectionHeader[Index];
    if (Section->SizeOfRawData == 0) {
      continue;
    }
    HashBase = (UINT8 *) (UINTN) ImageAddress + Section->PointerToRawData;
    HashSize = (UINTN) Section->SizeOfRawData;

    SHA1Update (&Sha1Ctx, HashBase, HashSize);

    SumOfBytesHashed += HashSize;
  }
/// ---
  //
  // 16.  If the file size is greater than SUM_OF_BYTES_HASHED, there is extra
  //      data in the file that needs to be added to the hash. This data begins
  //      at file offset SUM_OF_BYTES_HASHED and its length is:
  //             FileSize  -  (CertDirectory->Size)
  //
  if (ImageSize > SumOfBytesHashed) {
    HashBase = (UINT8 *) (UINTN) ImageAddress + SumOfBytesHashed;

    if (NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_SECURITY) {
      CertSize = 0;
    } else {
      if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        //
        // Use PE32 offset.
        //
        CertSize = Hdr.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      } else {
        //
        // Use PE32+ offset.
        //
        CertSize = Hdr.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
      }
    }

    if (ImageSize > CertSize + SumOfBytesHashed) {
      HashSize = (UINTN) (ImageSize - CertSize - SumOfBytesHashed);

      SHA1Update (&Sha1Ctx, HashBase, HashSize);
    } else if (ImageSize < CertSize + SumOfBytesHashed) {
      goto Finish;
    }
  }

  //
  // 17.  Finalize the SHA hash.
  //
///  SHA1Final (Sha1Ctx, (UINT8 *) &TcgEvent->Digest);
  SHA1Final(results, &Sha1Ctx);

  Status = EFI_SUCCESS;

Finish:
        free(ImageAddress);
        /* Print the digest as one long hex value */
        if (Status == EFI_SUCCESS) {
                for (n = 0; n < SHA1_DIGEST_LENGTH; n++)
                      printf("%02x", results[n]);
                putchar('\n');
                return 0;
        } else {
                fprintf(stderr, "error: status %lu\n", Status);
                return 6;
        }
}

int
main (int argc, char **argv)
{
  int efi = 0;
  int pcr = 0;
  char *cvalue = NULL;
  int index;
  int c;
  int hpWorkaround = 0;
  int result = 99;

  opterr = 0;

  while ((c = getopt (argc, argv, "el:p:o:t:i:c:h")) != -1)
    switch (c)
      {
      case 'e': // UEFI = yes (defaults to NO)
        efi = 1;
        break;
      case 'l': // PCR[4]: MBR code sha1sum OR EFI loader sha1sum (loaded by BIOS/UEFI)
        pcr = 4;
        cvalue = optarg; // EFI loader path OR MBR boot drive (like /dev/sda)
        break;
      case 'p': // PCR[5]: MBR data sha1sum OR GPT sha1sum (loaded by BIOS/UEFI)
        pcr = 5;
        cvalue = optarg; // GPT drive OR MBR boot drive (like /dev/sda)
        break;
      case 'o': // PCR[8]: GRUB stage 1 (usually 512 bytes right after MBR). Not possible with UEFI!
        pcr = 8;
        cvalue = optarg; // GPT drive OR MBR boot drive (like /dev/sda)
        break;
      case 't': // PCR[9]: GRUB stage 2 (usually 512 bytes right after MBR). Not possible with UEFI!
        pcr = 9;
        cvalue = optarg; // GPT drive OR MBR boot drive (like /dev/sda)
        break;
      case 'h': // PCR[9]: GRUB stage 2 (usually 512 bytes right after MBR). Not possible with UEFI!
        hpWorkaround = 1;
        break;
      case 'i':
        pcr = 14; // PCR[14]: kernel, then initrd (sha1sums)
        break;
      case 'c':
        pcr = 15; // PCR[15]: kernel cmdline (from grub or other place?)
        break;
      case '?':
        if (optopt == 'l')
          fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
        abort ();
      }

  fprintf (stderr, "EFI = %d, PCR = %d, Filename = %s\n",
          efi, pcr, cvalue);

  for (index = optind; index < argc; index++)
    fprintf (stderr, "Non-option argument %s\n", argv[index]);


  switch (pcr) {
    case 4:
      if (efi) {
        result = CalculatePEHash(cvalue);
      } else {
        result = CalculateMBRIPLHash(cvalue);
      }
      break;
   case 5:
      if (efi) {
        result = CalculateGPTHash(cvalue);
      } else {
        result = CalculateMBRDataHash(cvalue);
      }
      break;
   case 8:
        if (efi) {
           fprintf(stderr, "PCR[8] measurement NOT SUPPORTED for UEFI. Use sha1sum instead.\n");
        } else {
           result = CalculateGrubStage15Hash(cvalue);
        }
        break;
   case 9:
        if (efi) {
           fprintf(stderr, "PCR[9] measurement NOT SUPPORTED for UEFI. Use sha1sum instead.\n"); // calculate sha1sum of provided file here
        } else {
           result = CalculateGrubStage2Hash(cvalue, hpWorkaround);
        }
        break;
   case 14:
   case 15:
   default:
     fprintf(stderr, "EFI = %d, PCR = %d not supported yet\n", efi, pcr);
  }

  return result;
}