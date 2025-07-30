#pragma once
#if defined(_WIN32)
#include "Windows.h"
#endif
#include <stdio.h>

#define  CRT_SECURE_NO_WARNINGS
#define  MACSPACER            3
#define  IPv4                 4   
#define  IPv6SPACER           5
#define  MAC                  6
#define  IPv6                16
#define  MACArr              18
#define  IPv4Arr             17
#define  IPv6Arr             40
#define  HEX                 16
#define  DECIMAL             10

#ifndef _WIN32

typedef bool BOOLEAN;
typedef void VOID;

#endif

typedef unsigned char  Uchar;

typedef unsigned char *pUchar;

typedef unsigned short Ushort;

#ifdef WIN32
typedef NTSTATUS(NTAPI *fnRtlIpv4StringToAddressA)
(
	       PCSTR   S,
	       BOOLEAN Strict,
	       PCSTR  *Terminator,
	       PVOID   Addr
);

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
           PCSTR  S,
	       PCSTR *Terminator,
	       PVOID  Addr
);

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)
(
	       PCSTR  S,
	       PCSTR *Terminator,
	       PVOID  Addr
);

BOOLEAN RtlMacToStrA
(
	IN     PCHAR   MacArray[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PBYTE  *ppDAddress,
	   OUT SIZE_T *pDSize
);

BOOLEAN RtlIpv4toStrA
(
	IN     PCHAR   Ipv4Array[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PBYTE* pClearPayloadAddress,
	   OUT PSIZE_T psClearPayloadSize
);

BOOLEAN RtlIpv6ToStrA
(
	IN     CHAR   *Ipv6AddressesArray[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PBYTE  *pCleanPayloadAddress,
	   OUT PSIZE_T pClearPayloadSize
);

#endif

BOOLEAN PadDownPayload
(
	IN OUT pUchar *pPayload,
	IN     size_t  sPaddedSize,
	IN     Uchar   usPaddingAmount,
	IN     Uchar   IPv
);

BOOLEAN PadUpPayload
(
	IN OUT pUchar *pPayload,
	   OUT size_t *sNewPayloadSize,
	IN     size_t  sOldPayloadSize,
	IN     Uchar   usModulusMinusRemainder,
	IN	   Uchar   IPv
);

VOID FreePayloadArray
(
	IN     pUchar *pPayload_arr[],
	IN     size_t  sPayloadAssumedSize
);

BOOLEAN ObfuscatePayloadMAC
(
	IN     pUchar  pPayload,
	   OUT pUchar *pObfuscatedPayloadArray[],
	IN     size_t  sOriginalPayloadSize,
	   OUT size_t *sPaddedPayloadSize,
	   OUT size_t *sObfuscatedPayloadSize
);

BOOLEAN ObfuscatePayloadIPv4
(
	IN     pUchar  pPayload,
	   OUT pUchar *pObfuscatedPayloadArray[],
	IN     size_t  sOriginalPayloadSize,
	   OUT size_t *sPaddedPayloadSize,
	   OUT size_t *sObfuscatedPayload
);

BOOLEAN ObfuscatePayloadIPv6
(
	IN     pUchar  pPayload,
	   OUT pUchar *pObfuscatedPayloadArray[],
	IN     size_t  sOriginalPayloadSize,
	   OUT size_t *sPaddedPayloadSize,
	   OUT size_t *sObfuscatedPayloadSize
);

BOOLEAN DeobfuscatePayloadMAC
(
	   OUT pUchar *pClearPayloadAddress,
	IN     pUchar  pObfuscatedPayloadArray[],
	IN     size_t  sObfuscatedPayloadSize,
	   OUT size_t *sClearPayloadSize,
	IN     Uchar   ucPaddedBytes
);

BOOLEAN DeobfuscatePayloadIPv4
(
	   OUT pUchar *pClearPayload,
	IN     pUchar  pObfuscatedPayload[],
	IN     size_t  sObfuscatedPayloadSize,
	   OUT size_t *sClearPayloadSize,
	IN     Uchar   ucPaddedBytes
);

Uchar DecimalToByte
(
	   OUT pUchar pClearAddress,
	IN     pUchar Address,
	IN     short  OrderOfMagnitudeTracker
);


BOOLEAN DeobfuscatePayloadIPv6
(
	   OUT pUchar *pClearPayload,
	IN     pUchar  pObfuscatedPayloadArray[],
	IN     size_t  sObfuscatedPayloadSize,
	   OUT size_t *sClearPayloadSize,
	IN     Uchar   ucPaddedBytes
);

Uchar HexToChar
(
	IN    Uchar candidate
);