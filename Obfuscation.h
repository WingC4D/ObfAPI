#pragma once
#include <Windows.h>
#include <stdio.h>

#define CRT_SECURE_NO_WARNINGS
#define  IPv4   4   
#define  MAC    6
#define  IPv6   16

typedef NTSTATUS(NTAPI *fnRtlIpv4StringToAddressA)
(
	IN  PCSTR		S,
	IN  BOOLEAN		Strict,
	IN  PCSTR      *Terminator,
	IN  PVOID		Addr
);

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR		S,
	PCSTR* Terminator,
	PVOID		Addr
);

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)
(
	IN  PCSTR  S,
	IN  PCSTR *Terminator,
	IN  PVOID  Addr
);

boolean PadDownPayload
(
	IN OUT unsigned char **pPayload,
	IN     size_t          sPaddedSize,
	IN     unsigned short  usPaddingAmount,
	IN     unsigned char   IPv
);

boolean PadUpPayload
(
	IN OUT unsigned char **pPayload,
	OUT    size_t         *sNewPayloadSize,
	IN     size_t          sOldPayloadSize,
	IN     unsigned short  usModulusMinusRemainder,
	IN	   unsigned short  IPv
);

void FreePayloadArray
(
	IN     unsigned char** pPayload_arr[],
	IN     size_t          sPayloadAssumedSize
);

boolean ObfuscatePayloadMAC
(
	IN  unsigned char  *pPayload,
	OUT unsigned char **pObfuscatedPayload[],
	IN  size_t          sOriginalPayloadSize,
	OUT size_t         *sPaddedPayloadSize,
	OUT size_t         *sObfuscatedPayloadSize
);

BOOLEAN RtlMacToStrA
(
	IN CHAR* MacArray[],
	IN SIZE_T NmbrOfElements,
	IN  UCHAR   ucPaddedBytes,
	OUT PBYTE* ppDAddress,
	OUT SIZE_T* pDSize
);

boolean ObfuscatePayloadIPv4(
	IN     unsigned char  *pPayload,
	OUT    unsigned char **pObfuscatedPayload[],
	IN     size_t          sOriginalPayloadSize,
	OUT    size_t         *sPaddedPayloadSize,
	OUT    size_t         *sObfuscatedPayload
);

BOOLEAN RtlIpv4toStrA
(
	IN  PCHAR   Ipv4Array[],
	IN  SIZE_T  NmbrOfElements,
	IN  UCHAR   ucPaddedBytes,
	OUT PBYTE* pClearPayloadAddress,
	OUT PSIZE_T psClearPayloadSize
);

boolean ObfuscatePayloadIPv6
(
	IN     unsigned char  *pPayload,
	OUT    unsigned char **pOfusctedPayloadArray[],
	IN     size_t          sOriginalPayloadSize,
	OUT    size_t         *sPaddedPayloadSize,
	OUT    size_t         *sObfuscatedPayloadSize
);

BOOLEAN RtlIpv6ToStrA
(
	IN  CHAR   *Ipv6AddressesArray[],
	IN  SIZE_T  NmbrOfElements,
	IN  UCHAR   ucPaddedBytes,
	OUT PBYTE  *pCleanPayloadAddress,
	OUT PSIZE_T pClearPayloadSize
);

boolean DeobfuscatePayloadMAC
(
	OUT unsigned char** pClearPayloadAddress,
	IN  unsigned char* pObfuscatedPayloadArray[],
	IN  size_t          sObfuscatedPayloadSize,
	OUT size_t* sClearPayloadSize,
	IN  unsigned char   ucPaddedBytes
);

boolean DeobfuscatePayloadIPv4
(
	OUT unsigned char  *pClearPayload[],
	IN  unsigned char  *pObfuscatedPayload,
	IN  size_t          sObfuscatedPayloadSize,
	OUT size_t         *sClearPayloadSize,
	IN  unsigned char   ucPaddedBytes
);

unsigned char DecimalToByte
(
	OUT unsigned char *pClearAddress,
	IN  unsigned char *Address,
	IN  short          OrderOfMagnitudeTracker
);


boolean DeobfuscatePayloadIPv6
(
	OUT    unsigned char  *pClearPayload[],
	IN     unsigned char  *pObfuscatedPayloadArray[],
	IN     size_t          sObfuscatedPayloadSize,
	OUT    size_t         *sClearPayloadSize,
	IN     unsigned char   ucPaddedBytes
);

unsigned  char HexToChar
(
	IN unsigned char candidate
);