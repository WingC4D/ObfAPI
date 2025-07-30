#include "Obfuscation.h"
#ifdef _WIN32
//"LotL MAC Windows" Implementation
BOOLEAN RtlMacToStrA
(
	IN     PUCHAR  pPayloadArray[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PUCHAR *pClearPayloadAddress,
	   OUT PSIZE_T pClearPayloadSize
)
{
	if (!pPayloadArray || !NmbrOfElements || !*pClearPayloadAddress || !pClearPayloadSize) return FALSE;

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

	for (SIZE_T i = 0; i < NmbrOfElements; i++)
	{
		if (pRtlEthernetStringToAddressA((char*)pPayloadArray[i], &Terminator, *pClearPayloadAddress + i * MAC) != 0) return FALSE;
	}
	if (ucPaddedBytes)
	{
		if (!PadDownPayload(pClearPayloadAddress, strlen((char*)*pClearPayloadAddress), ucPaddedBytes, MAC)) goto _cleanup;
	}
	if ((*pClearPayloadSize = strlen((char*)*pClearPayloadAddress)) != sBufferSize - 1 - ucPaddedBytes) goto _cleanup;

	return TRUE;
_cleanup:
	LocalFree(*pClearPayloadAddress);
	*pClearPayloadAddress = NULL;
	return FALSE;
}

//"LotL IPv4 Windows" Implementation
BOOLEAN RtlIpv4toStrA
(
	IN     PCHAR   Ipv4Array[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PUCHAR *pClearPayloadAddress,
	   OUT PSIZE_T psClearPayloadSize
)
{
	if (!Ipv4Array || !NmbrOfElements || !pClearPayloadAddress || !psClearPayloadSize) return FALSE;

	SIZE_T sBufferSize = NmbrOfElements * IPv4 + 1;
	PCHAR  Terminator = NULL;
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");

	if (pRtlIpv4StringToAddressA == NULL) return FALSE;

	if (!*pClearPayloadAddress) *pClearPayloadAddress = LocalAlloc(LPTR, sBufferSize);
	else
	{
		LocalFree(*pClearPayloadAddress);
		if (!(*pClearPayloadAddress = LocalAlloc(LPTR, sBufferSize))) return FALSE;
	}
	memset(*pClearPayloadAddress, '\0', sBufferSize);

	for (int i = 0; i < NmbrOfElements; i++)
	{
		if (pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, *pClearPayloadAddress + i * IPv4) != 0) return FALSE;
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
	IN     PCHAR   Ipv6AddressesArray[],
	IN     SIZE_T  NmbrOfElements,
	IN     UCHAR   ucPaddedBytes,
	   OUT PUCHAR *pClearPayloadAddress,
	   OUT PSIZE_T psClearPayloadSize
)
{
	if (!Ipv6AddressesArray || !NmbrOfElements || !pClearPayloadAddress || !psClearPayloadSize) return FALSE;

	SIZE_T sBufferSize = NmbrOfElements * IPv6 + 1;
	LPSTR  Terminator = NULL;
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
		if (pRtlIpv6StringToAddressA(Ipv6AddressesArray[i], &Terminator, (char*)*pClearPayloadAddress + i * IPv6) != 0) return FALSE;
	}
	if (ucPaddedBytes)
	{
		if (!PadDownPayload(pClearPayloadAddress, sBufferSize - 1, ucPaddedBytes, IPv6)) goto _cleanup;
	}
	if ((*psClearPayloadSize = strlen((char*)*pClearPayloadAddress)) != sBufferSize - ucPaddedBytes - 1) goto _cleanup;

	return TRUE;
_cleanup:
	LocalFree(*pClearPayloadAddress);
	*pClearPayloadAddress = NULL;
	return FALSE;
}
#endif

//PayloadArrayReleaser
VOID FreePayloadArray
(
	IN     pUchar *pPayload_arr[],
	IN     size_t  sPayloadAssumedSize
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
BOOLEAN PadDownPayload
(
	IN OUT pUchar *pPayload,
	IN     size_t  sPaddedSize,
	IN     Uchar   ucPaddingAmount,
	IN     Uchar   IPv
)
{
	pUchar pClearPayload;
	if (!(pClearPayload = LocalAlloc(LPTR, 1 + sPaddedSize - ucPaddingAmount))) return  FALSE;
	size_t
		sPaddedPayloadIndex,
		sClearPayloadIndex,
		sIndexSpacer = (sPaddedSize - ucPaddingAmount) / (ucPaddingAmount + 1);

	memset(pClearPayload, '\0', 1 + sPaddedSize - ucPaddingAmount);

	for (sPaddedPayloadIndex = 0 , sClearPayloadIndex = 0; sPaddedPayloadIndex < sPaddedSize - sIndexSpacer; sPaddedPayloadIndex += sIndexSpacer, sClearPayloadIndex += sIndexSpacer)
	{
		memcpy(pClearPayload + sClearPayloadIndex, *pPayload + sPaddedPayloadIndex, sIndexSpacer);
		sPaddedPayloadIndex++;
	}
	memcpy(pClearPayload + sClearPayloadIndex, *pPayload + sPaddedPayloadIndex - 1, sPaddedSize - ucPaddingAmount - sClearPayloadIndex);

	LocalFree(*pPayload);

	*pPayload = pClearPayload;

	return TRUE;
}

//"Custom Obfuscated Padding Logic" Adder Function
BOOLEAN PadUpPayload
(
	IN OUT pUchar *pPayloadAddress,
	   OUT size_t *sNewPayloadSize,
	IN     size_t  sOldPayloadSize,
	IN     Uchar   ucRemainder,
	IN     Uchar   IPv
)
{
	size_t
		sum,
		SumIndex,
		UnpaddedBlockStartIndex = 0, //can be modulo'd to have less data Traveling in the stack, still need to weigh memory to cpu cycles pros and cons.
		PaddedBlockStartIndex = 0,
		IndexSpacer = sOldPayloadSize / (ucRemainder + 1),
		PaddedBlockEndIndex = IndexSpacer;

	pUchar pObfuscatedPayload;

	if (!(pObfuscatedPayload = LocalAlloc(LPTR, sOldPayloadSize + ucRemainder + 1))) return FALSE;

	pObfuscatedPayload[sOldPayloadSize + ucRemainder] = '\0';

	for (Uchar iterations = 0; iterations < ucRemainder; iterations++)
	{
		memcpy(pObfuscatedPayload + PaddedBlockStartIndex, *pPayloadAddress + UnpaddedBlockStartIndex, IndexSpacer);

		for (sum = 0, SumIndex = UnpaddedBlockStartIndex; SumIndex < PaddedBlockEndIndex - iterations; SumIndex++) sum += *(*pPayloadAddress + SumIndex);

		if (PaddedBlockEndIndex < sOldPayloadSize + ucRemainder - 1) pObfuscatedPayload[PaddedBlockEndIndex] = (unsigned char)(sum % 256);

		UnpaddedBlockStartIndex += IndexSpacer;
		PaddedBlockStartIndex += IndexSpacer + 1;
		PaddedBlockEndIndex += IndexSpacer + 1;

	}
	size_t sPayloadLength = strlen((char*)pObfuscatedPayload);

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
BOOLEAN ObfuscatePayloadMAC
(
	IN     pUchar  pPayload,
	   OUT pUchar *pObfuscatedPayloadArray[],
	IN     size_t  sOriginalPayloadSize,
	   OUT size_t *sPaddedPayloadSize,   
	   OUT size_t *sObfuscatedPayloadSize
)
{
	if (!pPayload || !*pObfuscatedPayloadArray || !sPaddedPayloadSize || !sObfuscatedPayloadSize) return FALSE;

	Uchar  usRemainder;

	if ((usRemainder = MAC - sOriginalPayloadSize % MAC) != MAC)
	{
		if (!PadUpPayload(&pPayload, sPaddedPayloadSize, sOriginalPayloadSize, usRemainder, MAC)) return FALSE;
	}
	else *sPaddedPayloadSize = sOriginalPayloadSize;

	*sObfuscatedPayloadSize = *sPaddedPayloadSize * MAC + 1;

	size_t i, sNumOfElements = *sPaddedPayloadSize / MAC;

	if (*pObfuscatedPayloadArray) LocalFree((pUchar*) *pObfuscatedPayloadArray);

	if (!(*pObfuscatedPayloadArray = (pUchar *)LocalAlloc(LPTR, sNumOfElements * sizeof(pUchar)))) return FALSE;

	for (i = 0; i < sNumOfElements; i++)
	{
		if (!((*pObfuscatedPayloadArray)[i] = (pUchar)LocalAlloc(LPTR, MACArr)))
		{
			i--;
			goto _cleanup; 
		}
		if (!sprintf_s(
			(char*)(*pObfuscatedPayloadArray)[i],
			MACArr,
			"%.2X-%.2X-%.2X-%.2X-%.2X-%.2X",
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
		LocalFree((*pObfuscatedPayloadArray)[j]);
	}
	
	LocalFree((pUchar *)*pObfuscatedPayloadArray);
	*pObfuscatedPayloadArray = NULL;
	return FALSE;
}

//IPv4 obfuscation and padding wrapper
BOOLEAN ObfuscatePayloadIPv4
(
	IN     pUchar  pPayload,
	   OUT pUchar *pObfuscatedPayloadArray[],
	IN     size_t  sOriginalPayloadSize,
	   OUT size_t *sPaddedPayloadSize,
	   OUT size_t *sObfuscatedPayloadSize
)
{

	if (!pPayload || !sOriginalPayloadSize || !sPaddedPayloadSize ||!*pObfuscatedPayloadArray) return FALSE;

	if (pObfuscatedPayloadArray) LocalFree((pUchar*)*pObfuscatedPayloadArray);

	Uchar  ucRemainder;

	if ((ucRemainder = IPv4 - sOriginalPayloadSize % IPv4) != IPv4)
	{
		if (!PadUpPayload(&pPayload, sPaddedPayloadSize, sOriginalPayloadSize, ucRemainder, IPv4)) return FALSE;
	}
	else *sPaddedPayloadSize = sOriginalPayloadSize;

	*sObfuscatedPayloadSize = *sPaddedPayloadSize * IPv4 + 1;

	size_t sArrayIndex, sNumOfElements = *sPaddedPayloadSize / IPv4;

	if (!((*pObfuscatedPayloadArray = (unsigned char**)LocalAlloc(LPTR, sNumOfElements * sizeof(LPSTR))))) return FALSE;

	for (sArrayIndex = 0; sArrayIndex < sNumOfElements; sArrayIndex++)
	{
		if (!((*pObfuscatedPayloadArray)[sArrayIndex] = (pUchar)LocalAlloc(LPTR, IPv4Arr)))
		{
			sArrayIndex--;
			goto _cleanup;
		}
		if (!sprintf_s(
			(char*)(*pObfuscatedPayloadArray)[sArrayIndex],
			IPv4Arr,
			"%d.%d.%d.%d",
			pPayload[sArrayIndex * 4],
			pPayload[sArrayIndex * 4 + 1],
			pPayload[sArrayIndex * 4 + 2],
			pPayload[sArrayIndex * 4 + 3]
		)) goto _cleanup;
	}
	return TRUE;
	
_cleanup:
	for (size_t j = 0; j < sArrayIndex; j++)
	{
		LocalFree((*pObfuscatedPayloadArray)[j]);
	}
	LocalFree((pUchar*)*pObfuscatedPayloadArray);
	*pObfuscatedPayloadArray = NULL;
	return FALSE;
}

//IPv6 obfuscation and Padding wrapper
BOOLEAN ObfuscatePayloadIPv6
(
	IN     pUchar  pPayload,
	   OUT pUchar *pObfuscatedPayloadArray[],
	IN     size_t  sOriginalPayloadSize,
	   OUT size_t *sPaddedPayloadSize,
	   OUT size_t *sObfuscatedPayloadSize
)
{
	if (!pPayload || !*pObfuscatedPayloadArray || !sOriginalPayloadSize || !sPaddedPayloadSize) return FALSE;

	Uchar ucRemainder;

	if ((ucRemainder = IPv6 - (unsigned short)(sOriginalPayloadSize % IPv6)) != IPv6)
	{
		if (!PadUpPayload(&pPayload, sPaddedPayloadSize, sOriginalPayloadSize, ucRemainder, IPv6)) return FALSE;

	}
	else *sPaddedPayloadSize = sOriginalPayloadSize;

	size_t i, NumOfElements = *sPaddedPayloadSize / IPv6;

	*sObfuscatedPayloadSize = (size_t)((double)*sPaddedPayloadSize * 2.5 + 1);

	if (!(*pObfuscatedPayloadArray = (unsigned char **)LocalAlloc(LPTR, NumOfElements * sizeof(unsigned char*)))) return FALSE;

	for (i = 0; i < NumOfElements; i++)
	{
		if (!((*pObfuscatedPayloadArray)[i] = LocalAlloc(LPTR, IPv6Arr)))
		{
			i--;
			goto _cleanup;
		}
		if (!sprintf_s(
			(char*)(*pObfuscatedPayloadArray)[i],
			IPv6Arr,
			"%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X:%0.2X%0.2X",
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
		LocalFree((*pObfuscatedPayloadArray)[j]);
	}
	LocalFree(*pObfuscatedPayloadArray);
	*pObfuscatedPayloadArray = NULL;
	return FALSE;
}

//Portable Not-LotL Custom IPv4 Logic
BOOLEAN DeobfuscatePayloadIPv4
(
	    OUT pUchar *pClearPayload,
	IN  OUT pUchar  pObfuscatedPayload[],
	IN      size_t  sObfuscatedPayloadSize,
	    OUT size_t *psClearPayloadSize,
	IN      Uchar   ucPaddedBytes
)
{
	if (!pClearPayload || !pObfuscatedPayload || !psClearPayloadSize || !sObfuscatedPayloadSize) return FALSE;

	if (*pClearPayload) if (!LocalFree(*pClearPayload)) return FALSE;

	size_t sPaddedPayloadIndex = 0, sPaddedPayloadSize = (sObfuscatedPayloadSize - 1) / 4;

	if (!(*pClearPayload = LocalAlloc(LPTR, sPaddedPayloadSize + 1))) return FALSE;

	*(*pClearPayload + sPaddedPayloadSize) = '\0';

	for (size_t i = 0; i < sPaddedPayloadSize / IPv4; i++) 
	{
		Ushort
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
BOOLEAN DeobfuscatePayloadIPv6
(
	   OUT pUchar *pClearPayloadAddress,
	IN     pUchar  pObfuscatedPayloadArray[],
	IN     size_t  sObfuscatedPayloadSize,
	   OUT size_t *sClearPayloadSize,
	IN     Uchar   ucPaddedBytes
)
{
	if (!pClearPayloadAddress ||!pObfuscatedPayloadArray || !sClearPayloadSize || !sObfuscatedPayloadSize) return FALSE;

	size_t sPaddedSize = (size_t)((long double)(sObfuscatedPayloadSize - 1) / 2.5);

	if (!*pClearPayloadAddress) *pClearPayloadAddress = LocalAlloc(LPTR, sPaddedSize + 1);
	else
	{
		LocalFree(*pClearPayloadAddress);
		if (!(*pClearPayloadAddress = LocalAlloc(LPTR, sPaddedSize + 1))) return FALSE;
	}
	for (size_t sArrayIndex = 0; sArrayIndex < sPaddedSize / IPv6; sArrayIndex++)
	{
		size_t sAddressLength = strlen((char*)pObfuscatedPayloadArray[sArrayIndex]);
		for (size_t sAddressIndex = 0; sAddressIndex < sAddressLength; sAddressIndex++)
		{
			*(*pClearPayloadAddress + sAddressIndex * 2 + IPv6 * sArrayIndex)     = HexToChar(pObfuscatedPayloadArray[sArrayIndex][sAddressIndex * 5])              * HEX + HexToChar(pObfuscatedPayloadArray[sArrayIndex][sAddressIndex * IPv6SPACER + 1]);

			*(*pClearPayloadAddress + sAddressIndex * 2 + IPv6 * sArrayIndex + 1) = HexToChar(pObfuscatedPayloadArray[sArrayIndex][sAddressIndex * IPv6SPACER + 2]) * HEX + HexToChar(pObfuscatedPayloadArray[sArrayIndex][sAddressIndex * IPv6SPACER + 3]);

			*sClearPayloadSize = sAddressIndex + 1;
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
BOOLEAN DeobfuscatePayloadMAC
(
	   OUT pUchar  *pClearPayloadAddress,
	IN     pUchar   pObfuscatedPayloadArray[],
	IN     size_t   sObfuscatedPayloadSize,
	   OUT size_t  *sClearPayloadSize,
	IN     Uchar    ucPaddedBytes
)
{
	if (!pObfuscatedPayloadArray || !sClearPayloadSize || !*pClearPayloadAddress || !sObfuscatedPayloadSize) return FALSE;

	size_t sPaddedSize = (size_t)((long double)(sObfuscatedPayloadSize - 1) / MAC);

	if (!*pClearPayloadAddress) *pClearPayloadAddress = LocalAlloc(LPTR, sPaddedSize + 1);
	else
	{
		LocalFree(*pClearPayloadAddress);
		if (!(*pClearPayloadAddress = LocalAlloc(LPTR, sPaddedSize + 1))) return FALSE;
	}
	for (size_t sArrayIndex = 0; sArrayIndex < (sPaddedSize / MAC); sArrayIndex++)
	{
		size_t sAddressLength = (unsigned char) strlen((char*)pObfuscatedPayloadArray[sArrayIndex]);
		for (size_t sClearAddressIndex = 0; sClearAddressIndex < sAddressLength; sClearAddressIndex++)
		{
			*(*pClearPayloadAddress + sClearAddressIndex + MAC * sArrayIndex) = 
				HexToChar(pObfuscatedPayloadArray[sArrayIndex][MACSPACER * sClearAddressIndex]) * HEX + 
				HexToChar(pObfuscatedPayloadArray[sArrayIndex][MACSPACER * sClearAddressIndex + 1]);
			
			*sClearPayloadSize =  sArrayIndex + 1;
		}
	}
	if (ucPaddedBytes)
	{
		if (!PadDownPayload(pClearPayloadAddress, sPaddedSize, ucPaddedBytes, MAC)) goto _cleanup;
	}
	if ((*sClearPayloadSize = strlen((char*)*pClearPayloadAddress)) != sPaddedSize - ucPaddedBytes) goto _cleanup;

	return TRUE;
_cleanup:
	LocalFree(*pClearPayloadAddress);
	*pClearPayloadAddress = NULL;
	return FALSE;
}

//Portable IPv4 Logic Helper Function
Uchar DecimalToByte(
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
Uchar HexToChar
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