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
#include <iconv.h>

#include <efi.h>
#include <efilib.h>
#include <linux/uuid.h>
#include "include/efistruct.h"
#include "include/PeImage.h"
#include "include/UefiGpt.h"
#include "include/UefiTcgPlatform.h"

int
CP852toUTF16(char c, UINT16 *out)
{
        size_t in_bytes_left = 1;
        size_t out_bytes_available = 2;
        char *resbuff = calloc(1, 1);
        char *outbuff = calloc(2, 1);
        char *input_temp = resbuff;
        char *output_temp = outbuff;
        iconv_t cd;

        resbuff[0] = c;
        cd = iconv_open("UTF-16LE", "CP437"); // from CP437 to UTF-16

        iconv(cd, &input_temp, &in_bytes_left, &output_temp, &out_bytes_available);
        iconv_close(cd);
        *out = *(UINT16 *)outbuff;

        return 0;
}
int
UTF16toUTF8(UINT16 in, char **outbuff)
{
        size_t in_bytes_left = 2;
        size_t out_bytes_available = 5;
        UINT16 *resbuff = calloc(2, 1);
        *outbuff = calloc(5, 1);
        char *input_temp = (char *)resbuff;
        char *output_temp = *outbuff;
        iconv_t cd;

        *resbuff = in;
        cd = iconv_open("UTF-8", "UTF-16LE"); // from UTF-16 to UTF-8

        iconv(cd, &input_temp, &in_bytes_left, &output_temp, &out_bytes_available);
        iconv_close(cd);

        return 0;
}


void
PrintByte(UINT8 c)
{
    char *p;
    UINT16 word;

    WCHAR data[32] = {0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022, 0x25D8, 0x25CB, 0x25D9, 0x2642, 0x2640, 0x266A, 0x266B, 0x263C, 0x25BA, 0x25C4, 0x2195, 0x203C, 0x00B6, 0x00A7, 0x25AC, 0x21A8, 0x2191, 0x2193, 0x2192, 0x2190, 0x221F, 0x2194, 0x25B2, 0x25BC};
    if (c == 0) {
        word = 32; // ' '
    } else if (c < 0x20) {
        word = data[c-1]; // fetch from data table
    } else if (c == 0x7F) {
        word = 0x2302;
    } else {
        CP852toUTF16(c, &word);
    }
    UTF16toUTF8(word, &p);
    printf("%s", p);

}

char *
EventName(UINT32 EventID)
{
        char *S_EV_POST_CODE = "EV_POST_CODE";
        char *S_EV_NO_ACTION = "EV_NO_ACTION";
        char *S_EV_SEPARATOR = "EV_SEPARATOR";
        char *S_EV_ACTION = "EV_ACTION";
        char *S_EV_EVENT_TAG = "EV_EVENT_TAG";
        char *S_EV_S_CRTM_CONTENTS = "EV_S_CRTM_CONTENTS";
        char *S_EV_S_CRTM_VERSION = "EV_S_CRTM_VERSION";
        char *S_EV_CPU_MICROCODE = "EV_CPU_MICROCODE";
        char *S_EV_PLATFORM_CONFIG_FLAGS = "EV_PLATFORM_CONFIG_FLAGS";
        char *S_EV_TABLE_OF_DEVICES = "EV_TABLE_OF_DEVICES";
        char *S_EV_COMPACT_HASH = "EV_COMPACT_HASH";
        char *S_EV_IPL = "EV_IPL";
        char *S_EV_IPL_PARTITION_DATA = "EV_IPL_PARTITION_DATA";
        char *S_EV_NONHOST_CODE = "EV_NONHOST_CODE";
        char *S_EV_NONHOST_CONFIG = "EV_NONHOST_CONFIG";
        char *S_EV_NONHOST_INFO = "EV_NONHOST_INFO";
        char *S_EV_OMIT_BOOT_DEVICE_EVENTS = "EV_OMIT_BOOT_DEVICE_EVENTS";

        char *S_EV_EFI_VARIABLE_DRIVER_CONFIG = "EV_EFI_VARIABLE_DRIVER_CONFIG";
        char *S_EV_EFI_VARIABLE_BOOT = "EV_EFI_VARIABLE_BOOT";
        char *S_EV_EFI_BOOT_SERVICES_APPLICATION = "EV_EFI_BOOT_SERVICES_APPLICATION";
        char *S_EV_EFI_BOOT_SERVICES_DRIVER = "EV_EFI_BOOT_SERVICES_DRIVER";
        char *S_EV_EFI_RUNTIME_SERVICES_DRIVER = "EV_EFI_RUNTIME_SERVICES_DRIVER";
        char *S_EV_EFI_GPT_EVENT = "EV_EFI_GPT_EVENT";
        char *S_EV_EFI_ACTION = "EV_EFI_ACTION";
        char *S_EV_EFI_PLATFORM_FIRMWARE_BLOB = "EV_EFI_PLATFORM_FIRMWARE_BLOB";
        char *S_EV_EFI_HANDOFF_TABLES = "EV_EFI_HANDOFF_TABLES";

        char *S_UNKNOWN = "<UNKNOWN_EVENT>";

        switch (EventID) {
                case EV_POST_CODE: // 0x1
                        return S_EV_POST_CODE;
                        break;
                case EV_NO_ACTION: // 0x3
                        return S_EV_NO_ACTION;
                        break;
                case EV_SEPARATOR: // 0x4
                        return S_EV_SEPARATOR;
                        break;
                case EV_ACTION: // 0x5
                        return S_EV_ACTION;
                        break;
                case EV_EVENT_TAG: // 0x6
                        return S_EV_EVENT_TAG;
                        break;
                case EV_S_CRTM_CONTENTS: // 0x7
                        return S_EV_S_CRTM_CONTENTS;
                        break;
                case EV_S_CRTM_VERSION: // 0x8
                        return S_EV_S_CRTM_VERSION;
                        break;

                case EV_CPU_MICROCODE: // 0x9
                        return S_EV_CPU_MICROCODE;
                        break;
                case EV_PLATFORM_CONFIG_FLAGS: // 0xA
                        return S_EV_PLATFORM_CONFIG_FLAGS;
                        break;
                case EV_TABLE_OF_DEVICES: // 0xB
                        return S_EV_TABLE_OF_DEVICES;
                        break;
                case EV_COMPACT_HASH: // 0xC
                        return S_EV_COMPACT_HASH;
                        break;
                case EV_IPL: // 0xD
                        return S_EV_IPL;
                        break;
                case EV_IPL_PARTITION_DATA: // 0xE
                        return S_EV_IPL_PARTITION_DATA;
                        break;
                case EV_NONHOST_CODE: // 0xF
                        return S_EV_NONHOST_CODE;
                        break;
                case EV_NONHOST_CONFIG: // 0x10
                        return S_EV_NONHOST_CONFIG;
                        break;
                case EV_NONHOST_INFO: // 0x11
                        return S_EV_NONHOST_INFO;
                        break;
                case EV_OMIT_BOOT_DEVICE_EVENTS: // 0x12
                        return S_EV_OMIT_BOOT_DEVICE_EVENTS;
                        break;

                case EV_EFI_VARIABLE_DRIVER_CONFIG: // 0x80000001
                        return S_EV_EFI_VARIABLE_DRIVER_CONFIG;
                        break;
                case EV_EFI_VARIABLE_BOOT: // 0x80000002
                        return S_EV_EFI_VARIABLE_BOOT;
                        break;
                case EV_EFI_BOOT_SERVICES_APPLICATION: // 0x80000003
                        return S_EV_EFI_BOOT_SERVICES_APPLICATION;
                        break;
                case EV_EFI_BOOT_SERVICES_DRIVER: // 0x80000004
                        return S_EV_EFI_BOOT_SERVICES_DRIVER;
                        break;
                case EV_EFI_RUNTIME_SERVICES_DRIVER: // 0x80000005
                        return S_EV_EFI_RUNTIME_SERVICES_DRIVER;
                        break;
                case EV_EFI_GPT_EVENT: // 0x80000006
                        return S_EV_EFI_GPT_EVENT;
                        break;
                case EV_EFI_ACTION: // 0x80000007
                        return S_EV_EFI_ACTION;
                        break;
                case EV_EFI_PLATFORM_FIRMWARE_BLOB: // 0x80000008
                        return S_EV_EFI_PLATFORM_FIRMWARE_BLOB;
                        break;
                case EV_EFI_HANDOFF_TABLES: // 0x80000009
                        return S_EV_EFI_HANDOFF_TABLES;
                        break;
                default:
                        return S_UNKNOWN;
        }
}

long int
GetFileSizeByRead(FILE *fp)
{
        long unsigned int size, read;
        long int fileSize = -1;
        UINT8 byte;
        fseek(fp, 0L, SEEK_SET);
        size = sizeof(byte);
        do {
                fileSize++;
                read = fread(&byte, 1, size, fp);
        } while (read == size);
        return fileSize;
}


VOID *LoadFileIntoBuffer(char *filename, long int *bufferSize)
{
        long unsigned int size, read;
        FILE *fp;
        VOID *buff;

        *bufferSize = 0;

        fp = fopen(filename, "r");
        if (fp  == NULL) {
                printf("File not found.\n");
                return NULL;
        }
        size = GetFileSizeByRead(fp);
        printf("File has size %lu bytes.\n", size);
        fseek(fp, 0L, SEEK_SET);
        if (size == 0) {
                fclose(fp);
                return NULL;
        }
        buff = calloc(1, size);
        if (buff == NULL) {
                printf("Cannot allocate memory to load file.\n");
                fclose(fp);
                return NULL;
        }
        read = fread(buff, 1, size, fp);
        if (read != size) {
                printf("Expected %lu bytes, read %lu bytes. Bailing out.\n", size, read);
                fclose(fp);
                free(buff);
                return NULL;
        }
        fclose(fp);
        *bufferSize = size;
        return buff;
}

#define WIDE 32
long int
DecodeEntry(char *data, long int maxBytes)
{
        UINT32 PCR, EventID, DataLength = 0;
        UINT8 *MeasurementHash;

        // an entry in TCG1.2 is composed of:
        // 4 bytes = unsigned PCR ID
        // 4 bytes = unsigned Event ID
        // 20 bytes (sha1) = measurement hash
        // 4 bytes = unsigned "data length"
        // "data length" bytes = event data (might be measured data or other TCG event structures)
        // therefore a data structure must be at least 4+4+20+4 bytes long, let's check for that first
        if (maxBytes < (4+4+20+4)) return 0; // probably invalid data buffer

        PCR = *(UINT32 *)(data);
        data += 4;

        EventID = *(UINT32 *)(data);
        data += 4;

        MeasurementHash = (UINT8 *)(data);
        data += 20;

        DataLength = *(UINT32 *)(data);
        data += 4;

        // now the data must provide space for at least "DataLength" bytes - do they?
        if (maxBytes < (4+4+20+4+DataLength)) return 0; // no, they don't

        printf("PCR %d, EventId=%x (%s), DataLength=%d, Hash=", PCR, EventID, EventName(EventID), DataLength);
        for (int i = 0; i < 20; i++) {
                printf("%x", *(MeasurementHash+i));
        }
        printf("\n");

        // now print the data itself
        // use hexdump -C style: HexOffsetStart[8b]: 16x hexdumpbyte, space separated |16xprintout byte|
        for (unsigned int i = 0; i < DataLength; i += WIDE) {
                unsigned int j;
                // Print offset
                printf("%08x: ", i);
                // Print hexdumps
                for (j = i; (j < i+WIDE) && (j < DataLength); j++) {
                        printf("%02x ", *(UINT8 *)(data+j));
                }
                // fill in the rest of 16-hexbyte-prints by spaces
                for (; (j < i+WIDE); j++) {
                        printf("   ");
                }
                printf(" |");
                // Print chars
                for (j = i; (j < i+WIDE) && (j < DataLength); j++) {
                        UINT8 c = *(UINT8 *)(data+j);
                        if (c >= 0x20 && c < 0x7F) {
                                printf("%c", c);
                        } else {
                                PrintByte(c);
                        }
                }
                // fill in the rest of 16-hexbyte-prints by spaces
                for (; (j < i+WIDE); j++) {
                        printf(" ");
                }
                printf("|\n");
        }

        return 4+4+20+4+DataLength;
}

void
decodeFile(char *filename)
{
        char *fileData;
        long int fileSize, buffPosition = 0;
        long int bytesDecoded = 0;

        fileData = (char *)LoadFileIntoBuffer(filename, &fileSize);
        if (fileData == NULL) return;

        while (buffPosition < fileSize) {
                bytesDecoded = DecodeEntry(fileData, (fileSize-buffPosition));
                if (bytesDecoded <= 0) break; // failure has occured, let's get us out of here
                buffPosition += bytesDecoded;
                fileData += bytesDecoded;
        }
}

void
printBuffer(char *buffer, int bufSize)
{
}

int
main (int argc, char **argv)
{
  char *measurements = "/sys/kernel/security/tpm0/binary_bios_measurements";
  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, "f:")) != -1)
    switch (c)
      {
      case 'f': // specify filename (default = /sys/kernel/security/tpm0/binary_bios_measurements)
        measurements = optarg; // GPT drive OR MBR boot drive (like /dev/sda)
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

  printf ("Measuring %s...\n",
          measurements);

  decodeFile(measurements);

  return 0;
}