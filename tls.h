#ifndef _TLS_H
#define _TLS_H

#include <stdio.h>
#include <stdint.h>

void showTLSVersion(uint16_t version);
void showTLSType(uint8_t type);
int checkVersion(uint16_t version);
int checkType(uint8_t type);
int showHandshakeType(uint8_t type);
void showCipherSuites(uint16_t data);
void showExtensiontype(uint16_t data);
#endif
