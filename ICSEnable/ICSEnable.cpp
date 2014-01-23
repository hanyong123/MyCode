#include "ICSEnable.h"
#include "stdafx.h"
#include <objbase.h>
#include <netcon.h>
#include <stdio.h>
#include "comutil.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "comsuppw.lib") 

static INetSharingManager * pNSM = NULL;

 class NetShare
 {
 public:
	   INetConnection* pSharedConnection;
       INetConnection* pHomeConnection;
 };

HRESULT  ICS_Enable_Initialize()
{
	CoInitialize (NULL);
	CoInitializeSecurity (NULL, -1, NULL, NULL, 
                          RPC_C_AUTHN_LEVEL_PKT, 
                          RPC_C_IMP_LEVEL_IMPERSONATE,
                          NULL, EOAC_NONE, NULL);
	 HRESULT hr = ::CoCreateInstance (__uuidof(NetSharingManager),
                                     NULL,
                                     CLSCTX_ALL,
                                     __uuidof(INetSharingManager),
                                     (void**)&pNSM);
	 
	  return hr;
}

void  ICS_Enable_Destory()
{
	pNSM->Release();
	CoUninitialize ();
}

static INetSharingConfiguration* GetConfiguration(INetConnection* pNC)
{
	INetSharingConfiguration * pNSC = NULL;
	pNSM->get_INetSharingConfigurationForINetConnection(pNC,&pNSC);
	if( pNSM )
		return pNSC;
	else
		return NULL;
}

static void GetCurrentlySharedConnections(NetShare* pNetShare)
{
	HRESULT hr;
	INetSharingEveryConnectionCollection * pEnum = NULL;
	pNSM->get_EnumEveryConnection(&pEnum);
	IUnknown * pUnk = NULL;
	IEnumVARIANT * pEV = NULL;
	if( pEnum )
	{
		pEnum->get__NewEnum(&pUnk);
		pEnum->Release();
	}
	if (pUnk) 
	{
        hr = pUnk->QueryInterface (__uuidof(IEnumVARIANT),
                                            (void**)&pEV);
        pUnk->Release();
    }
	if(pEV)
	{
		VARIANT v;
		VariantInit (&v);

		bool flag1 = false;
		bool flag2 = false;
		while (S_OK == pEV->Next (1, &v, NULL))
		{
			INetConnection * pNC = NULL; 
			V_UNKNOWN (&v)->QueryInterface (__uuidof(INetConnection),
                                                           (void**)&pNC);
			if(pNC)
			{
				INetSharingConfiguration * pNSC = NULL;
				pNSC = GetConfiguration(pNC);
				if( pNSC )
				{
					VARIANT_BOOL  bEnable;
					pNSC->get_SharingEnabled(&bEnable);
					if( bEnable < 0)
					{
						SHARINGCONNECTIONTYPE  shareType;
						pNSC->get_SharingConnectionType(&shareType);
						if( shareType == ICSSHARINGTYPE_PUBLIC )
						{
							pNetShare->pSharedConnection = pNC;
							flag1 = true;
						}
						if( shareType == ICSSHARINGTYPE_PRIVATE)
						{
							pNetShare->pHomeConnection = pNC;
							flag2 = true;
						}
						if( flag1 && flag2 )
						{
							pNSC->Release();
							pEV->Release();
							return;
						}
					}
					pNSC->Release();
				}
				pNC->Release();
			}
		}
		pEV->Release();
	}
}

static INetConnection* FindConnectionByName(CString& name)
{
	HRESULT hr;
	INetSharingEveryConnectionCollection * pEnum = NULL;
	pNSM->get_EnumEveryConnection(&pEnum);
	IUnknown * pUnk = NULL;
	IEnumVARIANT * pEV = NULL;
	
	if( pEnum )
	{
		pEnum->get__NewEnum(&pUnk);
		pEnum->Release();
	}
	if (pUnk) 
	{
        hr = pUnk->QueryInterface (__uuidof(IEnumVARIANT),
                                            (void**)&pEV);
        pUnk->Release();
    }
	if(pEV)
	{
		VARIANT v;
		VariantInit (&v);
		while (S_OK == pEV->Next (1, &v, NULL))
		{
			if (V_VT (&v) == VT_UNKNOWN)
			{
				INetConnection * pNC = NULL; 
				V_UNKNOWN (&v)->QueryInterface (__uuidof(INetConnection),
                                                           (void**)&pNC);
				if(pNC)
				{
					INetConnectionProps * pNCP = NULL;
					pNSM->get_NetConnectionProps(pNC, &pNCP);
					if(pNCP)
					{
						BSTR  str;
						pNCP->get_Name(&str);
						char* lpszText2 = _com_util::ConvertBSTRToString(str); 
						CString strConNname(lpszText2);
						printf("%s\n",lpszText2);
						if( strConNname.Compare(name) == 0)
						{
							pNCP->Release();
							pEV->Release();
							return pNC;
						}
						pNCP->Release();
					}
					pNC->Release();
				}
			}
		}
		pEV->Release();
	}
	return NULL;
}


bool EnableICS(CString& shared,CString& home)
{
	INetConnection* pConnectionToShare = FindConnectionByName(shared);
	if( pConnectionToShare == NULL )
		return false;
	INetConnection* pHomeConnection  = FindConnectionByName(home);
	if( pHomeConnection == NULL )
		return false;

	NetShare netshare;
	netshare.pHomeConnection = NULL;
	netshare.pSharedConnection = NULL;
	GetCurrentlySharedConnections(&netshare);
	if( netshare.pHomeConnection )
	{
		INetSharingConfiguration* pHome = GetConfiguration(netshare.pHomeConnection);
		pHome->DisableSharing();
		pHome->Release();
		netshare.pHomeConnection->Release();
	}
	if( netshare.pSharedConnection )
	{
		INetSharingConfiguration* pPub = GetConfiguration(netshare.pSharedConnection);
		pPub->DisableSharing();
		pPub->Release();
		netshare.pSharedConnection->Release();
	}
	
	
	INetSharingConfiguration* pHc = GetConfiguration(pHomeConnection);
	if( pHc->EnableSharing(ICSSHARINGTYPE_PRIVATE) != S_OK)
	{
		printf("homeconnection fail\n");
		return false;
	}
	
	INetSharingConfiguration* pSc = GetConfiguration(pConnectionToShare);
	if( pSc->EnableSharing(ICSSHARINGTYPE_PUBLIC) != S_OK)
	{
		printf("public connection fail\n");
		return false;
	}
	

	pConnectionToShare->Release();
	pHomeConnection->Release();
	pSc->Release();
	pHc->Release();
	return true;
}