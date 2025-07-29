#include "Obfuscation.h"

//PayloadArrayReleaser
void FreePayloadArray
(
	IN     unsigned char **pPayload_arr[],
	IN     size_t          sPayloadAssumedSize
)
{
	for (size_t i = 0; i < sPayloadAssumedSize; i++) 
	{
		if (!(*pPayload_arr)[i]) break;
		LocalFree((*pPayload_arr)[i]);
	}
	LocalFree(*pPayload_arr);
	*pPayload_arr = NULL;
}

//"Custom Obfuscated Padding Logic" Remover Function
boolean PadDownPayload
(
	IN OUT unsigned char **pPayload,
	IN     size_t          sPaddedSize,
	IN     unsigned char   ucPaddingAmount,
	IN     unsigned char   IPv
)
{
	unsigned char *pClearPayload;

	if (!(pClearPayload = LocalAlloc(LPTR, 1 + sPaddedSize - ucPaddingAmount))) return  FALSE;

	unsigned int IndexSpacer = (unsigned int)((sPaddedSize - ucPaddingAmount) / (ucPaddingAmount + 1));

	size_t sPaddedPayloadIndex, sClearPayloadIndex;

	memset(pClearPayload, '\0', 1 + sPaddedSize - ucPaddingAmount);

	for (sPaddedPayloadIndex = 0 , sClearPayloadIndex = 0; sPaddedPayloadIndex < sPaddedSize - IndexSpacer; sPaddedPayloadIndex += IndexSpacer, sClearPayloadIndex += IndexSpacer)
	{
		memcpy(pClearPayload + sClearPayloadIndex, *pPayload + sPaddedPayloadIndex, IndexSpacer);
		sPaddedPayloadIndex++;
	}
	memcpy(pClearPayload + sClearPayloadIndex, *pPayload + sPaddedPayloadIndex - 1, sPaddedSize - ucPaddingAmount - sClearPayloadIndex);

	LocalFree(*pPayload);

	*pPayload = pClearPayload;

	return TRUE;
}

//"Custom Obfuscated Padding Logic" Adder Function
boolean PadUpPayload
(
	IN OUT unsigned char      **pPayloadAddress,
	   OUT size_t              *sNewPayloadSize,
	IN     const size_t         sOldPayloadSize,
	IN     const unsigned char  ucRemainder,
	IN     const unsigned short IPv
)
{
	size_t
		sum,
		SumIndex,
		sPayloadLength,
		UnpaddedBlockStartIndex = 0, //can be modulo'd to have less data Traveling in the stack, still need to weigh memory to cpu cycles pros and cons.
		PaddedBlockStartIndex = 0,
		IndexSpacer = sOldPayloadSize / (ucRemainder + 1),
		PaddedBlockEndIndex = IndexSpacer;

	unsigned char
		*pObfuscatedPayload;

	if (!(pObfuscatedPayload = LocalAlloc(LPTR, sOldPayloadSize + ucRemainder + 1))) return FALSE;

	pObfuscatedPayload[sOldPayloadSize + ucRemainder] = '\0';

	for (unsigned char iterations = 0; iterations < ucRemainder; iterations++)
	{
		memcpy(pObfuscatedPayload + PaddedBlockStartIndex, *pPayloadAddress + UnpaddedBlockStartIndex, IndexSpacer);

		for (sum = 0, SumIndex = UnpaddedBlockStartIndex; SumIndex < PaddedBlockEndIndex - iterations; SumIndex++) sum += *(*pPayloadAddress + SumIndex);

		if (PaddedBlockEndIndex < sOldPayloadSize + ucRemainder - 1) pObfuscatedPayload[PaddedBlockEndIndex] = (unsigned char)(sum % 256);

		UnpaddedBlockStartIndex += IndexSpacer;
		PaddedBlockStartIndex += IndexSpacer + 1;
		PaddedBlockEndIndex += IndexSpacer + 1;

	}
	sPayloadLength = strlen((char*)pObfuscatedPayload);

	if (sPayloadLength < sOldPayloadSize + ucRemainder)
	{
		memcpy(pObfuscatedPayload + PaddedBlockStartIndex, *pPayloadAddress + UnpaddedBlockStartIndex, sOldPayloadSize + ucRemainder - sPayloadLength);
	}
	LocalFree(*pPayloadAddress);
	*sNewPayloadSize = sOldPayloadSize + ucRemainder;
	*pPayloadAddress = pObfuscatedPayload;

	return TRUE;
}

//MAC obfuscation and padding wrapper
boolean ObfuscatePayloadMAC
(
	IN     unsigned char  *pPayload,
	   OUT unsigned char **pObfuscatedPayload[],
	IN     size_t          sOriginalPayloadSize,
	   OUT size_t         *sPaddedPayloadSize,   
	   OUT size_t         *sObfuscatedPayloadSize
)
{
	if (pObfuscatedPayload) LocalFree(*pObfuscatedPayload);

	if (!pPayload || !*pObfuscatedPayload || !sPaddedPayloadSize || !sObfuscatedPayloadSize) return FALSE;

	unsigned short  usRemainder;

	if ((usRemainder = MAC - sOriginalPayloadSize % MAC) != MAC)
	{
		if (!PadUpPayload(&pPayload, sPaddedPayloadSize, sOriginalPayloadSize, usRemainder, MAC)) return FALSE;
	}
	else *sPaddedPayloadSize = sOriginalPayloadSize;

	*sObfuscatedPayloadSize = *sPaddedPayloadSize * MAC + 1;

	size_t i, sNumOfElements = *sPaddedPayloadSize / MAC;

	if (!(*pObfuscatedPayload = LocalAlloc(LPTR, sNumOfElements * sizeof(unsigned char*)))) return FALSE;

	for (i = 0; i < sNumOfElements; i++)
	{
		if (!(pObfuscatedPayload[i] = (unsigned char*)LocalAlloc(LPTR, 18)))
		{
			i--;
			goto _cleanup; 
		}
		if (!sprintf_s(
			(char*)pObfuscatedPayload[i],
			18,
			"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X\0",
			pPayload[i * 6],
			pPayload[i * 6 + 1],
			pPayload[i * 6 + 2],
			pPayload[i * 6 + 3],
			pPayload[i * 6 + 4],
			pPayload[i * 6 + 5]
		)) goto _cleanup;
	}
	return TRUE;

_cleanup:
	for (size_t j = 0; j < i; j++)
	{
		LocalFree((*pObfuscatedPayload)[j]);
	}
	LocalFree(*pObfuscatedPayload);
	*pObfuscatedPayload = NULL;
	return FALSE;
}


//IPv4 obfuscation and padding wrapper
boolean ObfuscatePayloadIPv4
(
	IN     unsigned char  *pPayload,
	   OUT unsigned char **pObfuscatedPayload[],
	IN     size_t          sOriginalPayloadSize,
	   OUT size_t         *sPaddedPayloadSize,
	   OUT size_t         *sObfuscatedPayloadSize
)
{
	if (pObfuscatedPayload) LocalFree(*pObfuscatedPayload);

	if (!*pPayload || !sOriginalPayloadSize || !sPaddedPayloadSize) return FALSE;

	unsigned char  usRemainder;

	if ((usRemainder = IPv4 - sOriginalPayloadSize % IPv4) != IPv4)
	{
		if (!PadUpPayload(&pPayload, sPaddedPayloadSize, sOriginalPayloadSize, usRemainder, IPv4)) return FALSE;
	}
	else *sPaddedPayloadSize = sOriginalPayloadSize;

	*sObfuscatedPayloadSize = *sPaddedPayloadSize * IPv4 + 1;

	size_t i, sNumOfElements = *sPaddedPayloadSize / IPv4;

	if (!((*pObfuscatedPayload = (unsigned char**)LocalAlloc(LPTR, sNumOfElements * sizeof(LPSTR))))) return FALSE;

	for (i = 0; i < sNumOfElements; i++)
	{
		if (!((*pObfuscatedPayload)[i] = (unsigned char*)LocalAlloc(LPTR, 18))) 
		{
			i--;
			goto _cleanup;
		}
		if (!sprintf_s(
			(char*)(*pObfuscatedPayload)[i],
			18,
			"%d.%d.%d.%d\0",
			pPayload[i * 4],
			pPayload[i * 4 + 1],
			pPayload[i * 4 + 2],
			pPayload[i * 4 + 3]
		)) goto _cleanup;
	}
	return TRUE;
	
_cleanup:
	for (size_t j = 0; j < i; j++)
	{
		LocalFree((*pObfuscatedPayload)[j]);
	}
	LocalFree(*pObfuscatedPayload);
	*pObfuscatedPayload = NULL;
	return FALSE;
}

//IPv6 obfuscation and Padding wrapper
boolean ObfuscatePayloadIPv6
(
	IN     unsigned char  *pPayload,
	   OUT unsigned char **pOfusctedPayloadArray[],
	IN     size_t          sOriginalPayloadSize,
	   OUT size_t         *sPaddedPayloadSize,
	   OUT size_t         *sObfuscatedPayloadSize
)
{
	if (!pPayload || !sOriginalPayloadSize || !sPaddedPayloadSize) return FALSE;

	unsigned short usRemainder;

	if ((usRemainder = IPv6 - (unsigned short)(sOriginalPayloadSize % IPv6)) != IPv6)
	{
		if (!PadUpPayload(&pPayload, sPaddedPayloadSize, sOriginalPayloadSize, usRemainder, IPv6)) return FALSE;

	}
	else *sPaddedPayloadSize = sOriginalPayloadSize;

	size_t i, NumOfElements = *sPaddedPayloadSize / IPv6;

	*sObfuscatedPayloadSize = (size_t)((double)*sPaddedPayloadSize * 2.5 + 1);

	if (!(*pOfusctedPayloadArray = (unsigned char **)LocalAlloc(LPTR, NumOfElements * sizeof(unsigned char*)))) return FALSE;

	for (i = 0; i < NumOfElements; i++)
	{
		if (!((*pOfusctedPayloadArray)[i] = LocalAlloc(LPTR, 41)))
		{
			i--;
			goto _cleanup;
		}
		if (!sprintf_s(
			(char*)(*pOfusctedPayloadArray)[i],
			41,
			"%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X\0",
			pPayload[i * 16],
			pPayload[i * 16 + 1],
			pPayload[i * 16 + 2],
			pPayload[i * 16 + 3],
			pPayload[i * 16 + 4],
			pPayload[i * 16 + 5],
			pPayload[i * 16 + 6],
			pPayload[i * 16 + 7],
			pPayload[i * 16 + 8],
			pPayload[i * 16 + 9],
			pPayload[i * 16 + 10],
			pPayload[i * 16 + 11],
			pPayload[i * 16 + 12],
			pPayload[i * 16 + 13],
			pPayload[i * 16 + 14],
			pPayload[i * 16 + 15]
		)) goto _cleanup;
	}
	return TRUE;
_cleanup:
	for (size_t j = 0; j < i; j++)
	{
		LocalFree((*pOfusctedPayloadArray)[j]);
	}
	LocalFree(*pOfusctedPayloadArray);
	*pOfusctedPayloadArray = NULL;
	return FALSE;
}

//"LotL MAC Windows" Implementation
BOOLEAN RtlMacToStrA
(
	IN     PUCHAR  MacArray[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PUCHAR *pClearPayloadAddress,
	   OUT SIZE_T *pClearPayloadSize
)
{
	fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlEthernetStringToAddressA");

	if (pRtlEthernetStringToAddressA == NULL) return FALSE;

	SIZE_T sBufferSize = NmbrOfElements * MAC + 1;

	if (!*pClearPayloadAddress) *pClearPayloadAddress = LocalAlloc(LPTR, sBufferSize);
	else
	{
		LocalFree(*pClearPayloadAddress);
		if (!(*pClearPayloadAddress = LocalAlloc(LPTR, sBufferSize))) return FALSE;
	}
	memset(*pClearPayloadAddress, '\0', sBufferSize);

	LPSTR Terminator = NULL;

	for (int i = 0; i < NmbrOfElements; i++)
	{
		if (pRtlEthernetStringToAddressA((char *)MacArray[i], &Terminator, *pClearPayloadAddress + i * MAC) != 0) return FALSE;
	}
	if (ucPaddedBytes)
	{
		if (!PadDownPayload(pClearPayloadAddress, strlen((char*)*pClearPayloadAddress), ucPaddedBytes, MAC)) goto _cleanup;
	}
	if ((*pClearPayloadSize = strlen((char *)*pClearPayloadAddress)) != sBufferSize - 1 - ucPaddedBytes) goto _cleanup;

	return TRUE;
_cleanup:
	LocalFree(*pClearPayloadAddress);
	*pClearPayloadAddress = NULL;
	return FALSE;
}

//"LotL IPv4 Windows" Implementation
BOOLEAN RtlIpv4toStrA
(
	IN     PCHAR  *Ipv4Array[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PUCHAR *pClearPayloadAddress,
	   OUT PSIZE_T psClearPayloadSize
)
{
	SIZE_T sBufferSize = NmbrOfElements * IPv4 + 1;
	PCHAR  Terminator = NULL;
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")),"RtlIpv4StringToAddressA");

	if (pRtlIpv4StringToAddressA == NULL) return FALSE;

	if (! *pClearPayloadAddress) *pClearPayloadAddress = LocalAlloc(LPTR, sBufferSize);
	else 
	{
		LocalFree(*pClearPayloadAddress);
		if (!(*pClearPayloadAddress = LocalAlloc(LPTR, sBufferSize))) return FALSE;
	}
	memset(*pClearPayloadAddress, '\0', sBufferSize);

	for (int i = 0; i < NmbrOfElements; i++)
	{
		if (pRtlIpv4StringToAddressA((*Ipv4Array)[i], FALSE, &Terminator, *pClearPayloadAddress + i * IPv4) != 0) return FALSE;
	}
	
	if (ucPaddedBytes != 0)
	{
		if (!PadDownPayload(pClearPayloadAddress, sBufferSize, ucPaddedBytes, IPv4)) goto _cleanup;
	} 
	if ((*psClearPayloadSize = strlen((char*)*pClearPayloadAddress)) != sBufferSize - 1 - ucPaddedBytes) goto _cleanup;

	return TRUE;

_cleanup:
	LocalFree(*pClearPayloadAddress);
	*pClearPayloadAddress = NULL;
	return FALSE;
}

//"LotL IPv6 Windows" Implementation
BOOLEAN RtlIpv6ToStrA
(
	IN     PCHAR  *Ipv6AddressesArray[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PUCHAR *pClearPayloadAddress,
	   OUT PSIZE_T pClearPayloadSize
)
{
	SIZE_T sBufferSize = NmbrOfElements * IPv6 + 1;
	BOOLEAN bState = FALSE;
	LPSTR  Terminator  = NULL;
	fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");

	if (pRtlIpv6StringToAddressA == NULL) return FALSE;

	if (!*pClearPayloadAddress) *pClearPayloadAddress = LocalAlloc(LPTR, sBufferSize);
	else
	{
		LocalFree(*pClearPayloadAddress);
		if (!(*pClearPayloadAddress = LocalAlloc(LPTR, sBufferSize))) return FALSE;
	}

	memset(*pClearPayloadAddress, '\0', sBufferSize);

	for (int i = 0; i < NmbrOfElements; i++)
	{
		if (pRtlIpv6StringToAddressA((*Ipv6AddressesArray)[i], &Terminator, (char*) *pClearPayloadAddress + i * IPv6) != 0) return FALSE;
	}
	if (ucPaddedBytes)
	{
		if (!PadDownPayload(pClearPayloadAddress, sBufferSize -1, ucPaddedBytes, IPv6)) goto _cleanup;
	}
	
	if ((*pClearPayloadSize = strlen((char *)*pClearPayloadAddress)) != sBufferSize - ucPaddedBytes -1) goto _cleanup;

	return TRUE;
_cleanup:
	LocalFree(*pClearPayloadAddress);
	*pClearPayloadAddress = NULL;
	return FALSE;
}

//Portable Not-LotL Custom IPv4 Logic
boolean DeobfuscatePayloadIPv4
(
	    OUT unsigned char **pClearPayload,
	IN  OUT unsigned char  *pObfuscatedPayload[],
	IN      size_t          sObfuscatedPayloadSize,
	    OUT size_t         *psClearPayloadSize,
	IN      unsigned char   ucPaddedBytes
)
{
	if (*pClearPayload) if (!LocalFree(*pClearPayload)) return FALSE;

	size_t sPaddedPayloadIndex = 0, sPaddedPayloadSize = (sObfuscatedPayloadSize - 1) / 4;

	if (!(*pClearPayload = LocalAlloc(LPTR, sPaddedPayloadSize + 1))) return FALSE;

	*(*pClearPayload + sPaddedPayloadSize) = '\0';

	for (size_t i = 0; i < sPaddedPayloadSize / IPv4; i++) 
	{
		unsigned short
			usAddressLength = (unsigned short)strlen((char*)pObfuscatedPayload[i]),
			usLastIndex = 0;
			
		for (unsigned short j = 0; j <= usAddressLength; j++)
		{
			if (j == usAddressLength || pObfuscatedPayload[i][j] == '.')
			{
				DecimalToByte(*pClearPayload + sPaddedPayloadIndex, pObfuscatedPayload[i] + usLastIndex, j - usLastIndex);
				usLastIndex = j + 1;
				sPaddedPayloadIndex++;
			}
		}
	}
	if (ucPaddedBytes)
	{
		if (!PadDownPayload(pClearPayload, sPaddedPayloadSize, ucPaddedBytes, IPv4)) goto _cleanup;
	}
	if ((*psClearPayloadSize = strlen((char*)*pClearPayload)) != sPaddedPayloadSize - ucPaddedBytes) goto _cleanup;
	return TRUE;
_cleanup:
	LocalFree(*pClearPayload);
	*pClearPayload = NULL;
	return FALSE;
}


//Portable Not-LotL Custom IPv6 Logic
boolean DeobfuscatePayloadIPv6
(
	   OUT unsigned char **pClearPayloadAddress,
	IN     unsigned char  *pObfuscatedPayloadArray[],
	IN     size_t          sObfuscatedPayloadSize,
	   OUT size_t         *sClearPayloadSize,
	IN     unsigned char   ucPaddedBytes
)
{
	size_t sPaddedSize = (size_t)((long double)(sObfuscatedPayloadSize - 1) / 2.5);

	if (!*pClearPayloadAddress) *pClearPayloadAddress = LocalAlloc(LPTR, sPaddedSize + 1);
	else
	{
		LocalFree(*pClearPayloadAddress);
		if (!(*pClearPayloadAddress = LocalAlloc(LPTR, sPaddedSize + 1))) return FALSE;
	}
	for (unsigned long long i = 0; i < sPaddedSize / IPv6; i++)
	{
		size_t sAddressLength = strlen((char*)pObfuscatedPayloadArray[i]);
		for (int j = 0; j < sAddressLength; j++)
		{
			*(*pClearPayloadAddress + j * 2 + IPv6 * i)     = HexToChar(*(pObfuscatedPayloadArray[i] + j * 5))     * 16 + HexToChar(*(pObfuscatedPayloadArray[i] + j * 5 + 1));

			*(*pClearPayloadAddress + j * 2 + IPv6 * i + 1) = HexToChar(*(pObfuscatedPayloadArray[i] + j * 5 + 2)) * 16 + HexToChar(*(pObfuscatedPayloadArray[i] + j * 5 + 3));

			*sClearPayloadSize = i + 1;
		}
	}
	if (ucPaddedBytes)
	{
		if (!PadDownPayload(pClearPayloadAddress, sPaddedSize, ucPaddedBytes, IPv6)) goto _cleanup;
	}
	if((*sClearPayloadSize = strlen((char *)*pClearPayloadAddress)) != sPaddedSize - ucPaddedBytes) goto _cleanup;

	return TRUE;
_cleanup:
	LocalFree(*pClearPayloadAddress);
	*pClearPayloadAddress = NULL;
	return FALSE;
}

//Portable Not-LotL Custom MAC Logic
boolean DeobfuscatePayloadMAC
(
	   OUT unsigned char **pClearPayloadAddress,
	IN     unsigned char  *pObfuscatedPayloadArray[],
	IN     size_t          sObfuscatedPayloadSize,
	   OUT size_t         *sClearPayloadSize,
	IN     unsigned char   ucPaddedBytes
)
{
	size_t sPaddedSize = (size_t)((long double)(sObfuscatedPayloadSize - 1) / MAC);

	if (!*pClearPayloadAddress) *pClearPayloadAddress = LocalAlloc(LPTR, sPaddedSize + 1);
	else
	{
		LocalFree(*pClearPayloadAddress);
		if (!(*pClearPayloadAddress = LocalAlloc(LPTR, sPaddedSize + 1))) return FALSE;
	}
	for (size_t sArrayIndex = 0; sArrayIndex < (sPaddedSize / MAC); sArrayIndex++)
	{
		unsigned char ucAddressLength = (unsigned char) strlen((char*)pObfuscatedPayloadArray[sArrayIndex]);
		for (unsigned char ucClearAddressIndex = 0; ucClearAddressIndex < ucAddressLength; ucClearAddressIndex++)
		{
			*(*pClearPayloadAddress + ucClearAddressIndex + MAC * sArrayIndex) = HexToChar(*(pObfuscatedPayloadArray[sArrayIndex] + 3 * ucClearAddressIndex)) * 16 + HexToChar(*(pObfuscatedPayloadArray[sArrayIndex] + 1 + 3 * ucClearAddressIndex ));

			*sClearPayloadSize = sArrayIndex + 1;
		}
	}
	if (ucPaddedBytes)
	{
		if (!PadDownPayload(pClearPayloadAddress, sPaddedSize, ucPaddedBytes, IPv6)) goto _cleanup;
	}
	if ((*sClearPayloadSize = strlen((char*)*pClearPayloadAddress)) != sPaddedSize - ucPaddedBytes) goto _cleanup;

	return TRUE;
_cleanup:
	LocalFree(*pClearPayloadAddress);
	*pClearPayloadAddress = NULL;
	return FALSE;
}

//Portable IPv4 Logic Helper Function
unsigned char DecimalToByte(
	   OUT unsigned char *pClearAddress,
	IN     unsigned char *Address,
	IN     short          OrderOfMagnitudeTracker
)
{
	unsigned char sum = 0;
	short sStratingPoint = OrderOfMagnitudeTracker;

	for (OrderOfMagnitudeTracker; OrderOfMagnitudeTracker > 0; OrderOfMagnitudeTracker--)
	{
		sum = (unsigned char)(sum * 10 + (Address[sStratingPoint - OrderOfMagnitudeTracker] - '0'));
	}
	*pClearAddress = sum;
}

//IPv6 & MAC Logic helper function
unsigned char HexToChar
(
	IN     unsigned char candidate
)
{
	unsigned char result;
	if (0 > (result = candidate - '0') || result > 9)
	{
		if (9 > (result = candidate - 'A' + 10) || result > 15)
		{
			if (9 > (result = candidate - 'a' + 10) || result > 15) return FALSE;
		}
	}
	return result;
}