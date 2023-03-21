#include "tls.h"

void showCipherSuites(uint16_t data)
{
    char buf[64];
    int code;
    FILE* fp =fopen("./cipher.dat", "r");
    for (int i = 0; i < 354; i++) {
        fscanf(fp, "%4x 	%s \n", &code, buf);
        if (code == data) {
            printf("Cipher Suite: %s (0x%4x)\n", buf, code);
            break;
        } 
    }
}

void showExtensiontype(uint16_t data)
{
    char buf[64];
    int code;
    FILE* fp =fopen("./exten.dat", "r");
    for (int i = 0; i < 32; i++) {
        fscanf(fp, "%s %d\n", buf, &code);
        if (code == data) {
            printf("Type:  %s (%d)\n", buf, code);
            break;
        } 
    }
}

int showHandshakeType(uint8_t type)
{
    switch (type)
    {
    case 0x01:
        printf("Handshake Type: Client Hello (1)\n");
        break;
    case 0x02:
        printf("Handshake Type: Server Hello (2)\n");
        break;
    case 0x0b:
        printf("Handshake Type: Certificate (11)\n");
        break;
    case 0x0c:
        printf("Handshake Type: Server Key Exchange (12)\n");
        break;
    case 0x0d:
        printf("Handshake Type: Certificate Request(13)\n");
        break;
    case 0x0e:
        printf("Handshake Type: Server Hello Done(14)\n");
        break;
    case 0x0f:
        printf("Handshake Type: Certificate Verifiy (15)\n");
        break;
    case 0x10:
        printf("Handshake Type: Client Key Exchange (16)\n");
        break;
    case 0x14:
        printf("Handshake Type: Finished (20)\n");
        break;
    default:
        printf("Handshake Protocol: Encrypted Handshake Message\n");
        return 1;
        break;
    }
    return 0;
}

int checkType(uint8_t type)
{
    switch (type)
    {
    case 0x14:
        return 20;
        break;
    case 0x15:
        return 21;
        break;
    case 0x16:
        return 22;
        break;
    case 0x17:
        return 23;
        break;
    default:
        return 0;
        break;
    }
}

int checkVersion(uint16_t version)
{
    switch (version)
    {
    case 0x0300:
        return 0x0300;
        break;
    case 0x0301:
        return 0x0301;
        break;
    case 0x0302:
        return 0x0303;
        break;
    case 0x0303:
        return 0x0303;
        break;
    default:
        return 0;
        break;
    }
}

void showTLSType(uint8_t type)
{
    printf("Content Type:");
    switch (type)
    {
    case 0x14:
        printf("Change Cipher Spec (20)\n");
        break;
    case 0x15:
        printf("Alert (21)\n");
        break;
    case 0x16:
        printf("Handshake (22)\n");
        break;
    case 0x17:
        printf("Application Data (23)\n");
        break;
    default:
        printf("Not TLS data\n");
        break;
    }
}

void showTLSVersion(uint16_t version)
{
    printf("Version: ");
    switch (version)
    {
    case 0x0300:
        printf("TLS 3.0 (0x0300)\n");
        break;
    case 0x0301:
        printf("TLS 1.0 (0x0301)\n");
        break;
    case 0x0302:
        printf("TLS 1.1 (0x0302)\n");
        break;
    case 0x0303:
        printf("TLS 1.2 (0x0303)\n");
        break;
    default:
        break;
    }
}

