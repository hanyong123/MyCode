#include "stdafx.h"
#include "EnumDevDef.h"
#include "RtlFunc.h"
#include "icsapi.h"
#include "GetWinVer.h"
#include <tlhelp32.h>
#include <Dbt.h>
#include "OneKeyWifiFun.h"
#include <cfgmgr32.h>
#include <SetupAPI.h>
#include "ICS_DhcpApi.h"

#pragma comment(lib,"RtlICS_DHCP.lib")
#pragma comment(lib, "RtlLib.lib")
#pragma comment(lib, "EnumDevLib.lib")
#pragma comment(lib, "RtlICS.lib")
#pragma comment(lib,"Setupapi.lib")

#define MAX_NAME_LEN 128
#define APProfileName "APProfile"

static char AP_Use_DefaultIP[100];
static char AP_Use_DefaultMask[100];

static char m_OffdevName[50];   //无线网卡的GUID
static CString g_strFolder;
static char m_ConnectionName[50];
static char g_DriverPath[300];
static int g_nVersion;
static CString g_ver;
static CString g_verInfo;
static CStringArray g_spportHW;
extern int PasswordHash (
						 char *password,
						 int passwordlength,
						 unsigned char *ssid,
						 int ssidlength,
						 unsigned char *output);


////////////////////////////////////////////////////内部调用函数/////////////////////////////////////////////////////////////////////

void GetRegValue(char *RegPath,char *ParameterName,int type,char *retbuffer,DWORD *buflen)
{
	HKEY key;
	DWORD rettype;
	LONG lRet=-1; //add by karl
	LONG lRet2=-1; //add by karl
	LONG lRet3=-1; //add by karl
	
	if(lRet2 !=0 && lRet3 !=0)
	{
		retbuffer[0]=0;
		lRet2=-1;
		if(!strcmp(RegPath,"Software\\RtWLan"))
		{
			char RegPath_USER[255];
			sprintf(RegPath_USER,"%s\\%s",RegPath,g_strFolder);
			lRet=RegOpenKeyEx(HKEY_LOCAL_MACHINE,RegPath_USER,0,KEY_READ,&key);
			if(lRet==0)
			{
				retbuffer[0]=0;
				lRet2=RegQueryValueEx(key,ParameterName,NULL,&(rettype=REG_SZ),(unsigned char *)retbuffer,buflen);
				RegCloseKey(key);
			}
		}
		
		if(lRet2 !=0)
		{
			RegOpenKeyEx(HKEY_LOCAL_MACHINE,RegPath,0,KEY_READ,&key);
			RegQueryValueEx(key,ParameterName,NULL,&(rettype=REG_SZ),(unsigned char *)retbuffer,buflen);
			RegCloseKey(key);
		}
	}
}

static int GetProcessID2(LPTSTR pszProcessName, DWORD& th32ParentProcessID)
{
	int nUIProcess=0;
    HANDLE hSnapshot = NULL;
	int nProcess=0;               
    __try
    {
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hSnapshot)
		{
            __leave;
        }
		
        PROCESSENTRY32 pe;
        ZeroMemory(&pe, sizeof(PROCESSENTRY32));
        pe.dwSize = sizeof(PROCESSENTRY32);
		
        BOOL bProcess = Process32First(hSnapshot, &pe);
        while (bProcess)
        {
            if (pe.szExeFile == StrStrI(pe.szExeFile, pszProcessName))
            {
				nProcess++;
            }
			
            bProcess = Process32Next(hSnapshot, &pe);
        }
		
        if (!bProcess)
        {
            __leave;
        }
		
    }
    __finally
    {
        if (INVALID_HANDLE_VALUE != hSnapshot)
        {
            CloseHandle(hSnapshot);
        }
    }
	return nProcess;
}

static CString GetAppPath()
{
	TCHAR pathtemp[512];
	GetModuleFileName(NULL,pathtemp,512);
	CString path = pathtemp;
	int i = path.ReverseFind('\\');
	path = path.Left(i+1);
	return path;
}

static void AP_ACM_LinkTemporaryProfile(WirelessConnect TemporaryProfile)
{
	// char XMLProfile[2000];
	char XMLProfileName[33];
	char XMLSSID[33];
	int ConnectionType;
	bool bNotSaveToACM = true;

	memset(XMLProfileName, 0 ,33);
	memcpy(XMLProfileName, TemporaryProfile.ProfileName, 33);
	memset(XMLSSID, 0 ,33);
	memcpy(XMLSSID, TemporaryProfile.SSID, 33);
	ConnectionType = TemporaryProfile.Flag.Flag.InfraMode;

#ifdef WIN7
	RT_ACM_LinkRtlProfileNew(&TemporaryProfile, XMLProfileName, XMLSSID, ConnectionType, bNotSaveToACM , 1);
#endif
}

static unsigned char *StringToHex(char *in,int inlen,unsigned char *out,int outlen,bool IsNum)
{
	#define Hex2Num(n)	(   ((n)>='a'&&(n)<='z')   ?   ( (n)-'a'+10 ):( (n)>='A'? (n)-'A'+10:(n)-'0' )   )
	int i,j;
	memset(out,0,outlen);
	
	if(IsNum)
	{
		for(i=inlen-1,j=0;i>=0 && j<outlen;i-=2)
		{
			if(i>0)
			{
				out[j]=Hex2Num(in[i-1]);
				out[j]<<=4;
			}
			out[j++]+=Hex2Num(in[i]);
		}
	}
	else
	{
		for(i=inlen-1,j=outlen-1;i>=0 && j>=0;i-=2)
		{
			if(i>0)
			{
				out[j]=Hex2Num(in[i-1]);
				out[j]<<=4;
			}
			out[j--]+=Hex2Num(in[i]);
		}
	}
	
	return out;
}

static bool GetConnectionName(char *szGUID,char *szConnectionName) //Add by Karl
{
	HKEY key;
	DWORD rettype,buflen;
	LONG lRet=-1;  
	LONG lRet2=-1;  
	LONG lRet3=-1;  
	
	char RegPath_USER[255];
	sprintf(RegPath_USER,"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",szGUID);
	lRet=RegOpenKeyEx(HKEY_LOCAL_MACHINE,RegPath_USER,0,KEY_READ,&key);
	if(lRet==0)
	{
		buflen=100;
		lRet2=RegQueryValueEx(key,"Name",NULL,&(rettype=REG_SZ),(unsigned char *)szConnectionName,&buflen);
		RegCloseKey(key);
	}
	
	if(lRet2==0)
		return true;
	else
		return false;
	
}

/////////////////////////////////////////////////////////////OneKeyWifi API////////////////////////////////////////////////////////////////////////
/*
初始化模块，要使用模块其他函数必须先调用这个函数
返回:
-1:GetWinVer fail
0:成功
*/
int OneKeyWifiInit()
{
	CString str=GetAppPath();
	int i = str.ReverseFind('\\');
	str = str.Left(i);
	int j = str.ReverseFind('\\');
	g_strFolder = str.Mid(j+1,i);
	if( !GetWinVer(g_ver,&g_nVersion, g_verInfo))
		return -1;

	CStdioFile file;
	CString strLine = "";
	CString str1 = "";
	file.Open("RTK_HWID.dat",CFile::modeRead);
	while(file.ReadString(strLine))
	{
		g_spportHW.Add(strLine);
		str1 = str1 + strLine+";";
	}
	str1.Delete(str1.GetLength()-1);
	file.Close();
#ifdef XP
	LONG lRet;
	HKEY key;
	HKEY key1;
	CString strpath = "SOFTWARE\\RtWLan";
	strpath.Format("SOFTWARE\\RtWLan\\%s",g_strFolder);
	lRet = RegOpenKey(HKEY_LOCAL_MACHINE,strpath,&key);
	if( lRet != 0)
	{
		RegOpenKey(HKEY_LOCAL_MACHINE,"SOFTWARE",&key);
		strpath.Format("RtWLan\\%s",g_strFolder);
		if( RegCreateKey(key,strpath,&key1) != 0)
		{
			return -1;
		}
		if( RegSetValueEx(key1,"DeviceID",NULL,REG_SZ,(unsigned char*)(LPCTSTR)str1,str1.GetLength()) != 0)
		{
			return -1;
		}
	}
#endif
	return 0;
}

/*
配置AP的参数，调用这个函数时网卡必须处于AP模式，就是说SWtoAPMode调用成功
-1:PasswordHash fail
-2:RT_AP_SetPassphrase fail
0:成功
*/
int ConfigVAP(CString& ssid,const char *PassWord,bool bHidssid)
{
	char buf[100];
	static WirelessConnect m_APProfile;

	memset(&m_APProfile, 0, sizeof(m_APProfile));
	strcpy(m_APProfile.ProfileName, "Access Point Mode");
	strcpy(m_APProfile.SSID, ssid.GetBuffer(ssid.GetLength()));
	strcpy(buf, m_APProfile.SSID);
	
	m_APProfile.Flag.Flag.Privacy = 1;
	m_APProfile.Flag.Flag.InfraMode = 1;
	m_APProfile.Channel = 9;
	m_APProfile.CapEx = 2;
	m_APProfile.GroupKeyCipherSuiteBitmap = 0x10;
	m_APProfile.AuthenticatedKeyManagementSuiteBitmap = 0x40;
	m_APProfile.Flag.Flag.AuthMode = 3; //WPA2
	m_APProfile.PairwiseKeyCipherSuiteBitmap = 0x10; // AES
	m_APProfile.Flag.Flag.EncMethod = 3; // AES

	int keylen = strlen(PassWord);
	memcpy(m_APProfile.wpa_psk_pass_phrase, PassWord, keylen);
	m_APProfile.wpa_psk_pass_phrase_length = keylen;
	m_APProfile.wpa_psk_pass_phrase[keylen] = 0;

	if( !PasswordHash(m_APProfile.wpa_psk_pass_phrase, m_APProfile.wpa_psk_pass_phrase_length,
			(unsigned char *)m_APProfile.SSID, strlen(m_APProfile.SSID), (UCHAR *)buf) )
			return -1;
	
	memcpy(m_APProfile.psk, buf, 32);

	int LinkStatus;
	int NetworkType;
	char ssid0[100];
	char bssid[6];
	RT_GetStatusLinkInfo(&LinkStatus,&NetworkType,ssid0,(char *)bssid);
	if (g_nVersion < WWin7X86)
	{
		RT_Disassociate();
		RT_SetNetworkType(m_APProfile.Flag.Flag.InfraMode);
	}
	else
	{
		RT_Disassociate();
		RT_SetNetworkType(1);
	}

#ifdef WIN7
	RT_ACM_Delete_AllProfiles();
	Sleep(1000);
#endif
	
	WirelessConnect AdHocProfileAP[1]={0};
	memcpy(&AdHocProfileAP[0],&m_APProfile,sizeof(WirelessConnect));
	memcpy(AdHocProfileAP[0].ProfileName,m_APProfile.SSID,50);
	AdHocProfileAP[0].Flag.Flag.InfraMode=false;
	
	AdHocProfileAP[0].Flag.Flag.AuthMode=0;
	AdHocProfileAP[0].Flag.Flag.Privacy=false;	// No Security
	AdHocProfileAP[0].Flag.Flag.EncMethod=0;		//Disabled	
	AdHocProfileAP[0].Flag.Flag.Use1x = 0;
	AP_ACM_LinkTemporaryProfile(AdHocProfileAP[0]);

	//--------------- Add By Karl ,Fix AP_Mode BUG
	int status,type;
	char Ssid[33],Bssid[6];
	int nLoop=1;
	for(int nn=0;nn<30;nn++)
	{
		Sleep(200);
		RT_GetStatusLinkInfo(&status,&type,Ssid,Bssid);
		if(status==2)
		{
			Sleep(200);
			break;
		}
		else if((nn>=30) && /*bProtocolDriverInitialized*/1 && nLoop)
		{
			nLoop--;
			AP_ACM_LinkTemporaryProfile(AdHocProfileAP[0]);
			nn=0;
		}
	}

	int RateAuto, Rate[4];
	RT_Set_Filter_Type(MAC_FILTER_DISABLE);
	RT_SetIsHidden_SSID(bHidssid);       //隐藏ssid
	RT_Set802_1xStatus(false);
	RT_GetStatusLinkInfo(&LinkStatus,&NetworkType,ssid0,(char *)bssid);
	RT_SetAUTOChannel(0);
	RT_SetChannel(m_APProfile.Channel);
	RT_SetPowerSaveMode(RT_GetPowerSaveMode());
	RT_GetRates(&RateAuto,&Rate[0],&Rate[1],&Rate[2],&Rate[3]);
	RT_SetRates(RateAuto!=0,Rate[0],Rate[1],Rate[2],Rate[3]);
	RT_SetPreambleMode(RT_GetPreambleMode());
	//////////////////////////////////////

	int	ssidlen = strlen(m_APProfile.SSID);
	//set PMK(PSK,SSID,BSSID) -> to 802.1x protocal driver
	NDISPROT_PSK_INFO	pskInfo;
	memcpy( pskInfo.ssid.Ssid, m_APProfile.SSID, ssidlen );
	pskInfo.ssid.SSIDLength = ssidlen;
	memcpy(pskInfo.bssid, m_APProfile.BSSID, 6);
	
	RT_SetAuthenticaionMode(4); //4:WPA2PSK-AES
	RT_SetEncryptionStatus(Ndis802_11Encryption3Enabled);
	RT_SetMHSecurityInfo(m_APProfile.Flag.Flag.InfraMode, 4, 3);
	
	if(m_APProfile.wpa_psk_pass_phrase_length != 64)
	{
		if( !RT_AP_SetPassphrase(m_APProfile.wpa_psk_pass_phrase, m_APProfile.wpa_psk_pass_phrase_length))
			return -2;
	}
	else
	{
		unsigned char   temppsk[32];
		StringToHex(m_APProfile.wpa_psk_pass_phrase,64,temppsk, 32,false);
		if( !RT_AP_SetPassphrase((char *)temppsk, 64))
			return -2;
	}
	RT_SetSSID(ssid.GetBuffer(ssid.GetLength()));   //设置AP SSID
	
	return 0;
}

/*
找到无线网卡并初始化，在调用OneKeyWifiInit后 调用其他函数之前 要先调用这个函数
这个函数也可以用于判断无线网卡是否拔出
0:成功
-1：找不到无线网卡
-2：初始化无线网卡失败
*/
bool bFind = false;
int FindAndInitDevice()
{
	int nAdapterCount=ShowDevice8180(NULL,NULL);
	if(nAdapterCount && !bFind)
	{
		RT_AdapterList AdapterList;
		RT_GetAdapterList(&AdapterList, true);
		if(AdapterList.AdapterNumber < 1)
		{
			return -1;
		}
		RT_SetDefaultAdapterIndex(0);
		bool binit=RT_Initialize(false);
		if(!binit)
		{
			return -2;
		}
		memcpy(m_OffdevName, AdapterList.InstanceID[0], 50);

		memset(g_DriverPath, 0, 300);
		RT_GetDriverPath(g_DriverPath);
		bFind = true;
		return 0;
	}
	else
	{
		if( nAdapterCount == 0 )
			return -1;

		if((bFind == true) &&  (nAdapterCount == 1))
			bFind = false;
	}
	return 0;
}


/*
自动设置系统的internet共享
-1:Get_Hi_Speed_Adapter fail
-2:ICS_SetShare fail
0:成功
*/
int AutoSetICS()
{
	if( g_nVersion < WWin7X86 )
	{
		printf("ICS_DHCP_Enable start\n");
		bool bRet = ICS_DHCP_Enable(m_OffdevName,"192.168.159.1","192.168.159.2","192.168.159.254");
		printf("ICS_DHCP_Enable end\n");
		//if( !bRet )
		//	return -2;
	}
	else
	{
		int nUIType = 0;
		bool ret=false;
		NetConnAvailable m_ConnPublicLAN[MAX_CONN];
		int m_nConnPublicLAN=0;
		CString strname;
		NetConnAvailable	AP_ConnPublicLAN;
		ret=ICS_GetInetConnWithoutRtlWlan(m_OffdevName, m_ConnPublicLAN, &m_nConnPublicLAN ,nUIType);
		for(int nn=0 ; nn < m_nConnPublicLAN ; nn++)
		{
			strname=m_ConnPublicLAN[nn].name;
			if(strname.Find("VMware")&&
				strname.Find("1394") &&
				(m_ConnPublicLAN[nn].characteristics!=0) && 
				(m_ConnPublicLAN[nn].characteristics!=0x9) && 
				(m_ConnPublicLAN[nn].status==2))
			{	
				memcpy(&AP_ConnPublicLAN , &m_ConnPublicLAN[nn] , sizeof(NetConnAvailable));
				strcpy(m_ConnectionName, AP_ConnPublicLAN.name);
				break;
			}
		}

		char szPrivateLAN[50];
		char szPublicLAN[MAX_NAME_LEN];
		int nEnable = 0;
		memset(szPrivateLAN,0,50);
		memset(szPublicLAN,0,MAX_NAME_LEN);
		bool RetOK=ICS_GetShare(&nEnable, szPrivateLAN, szPublicLAN);
		if(RetOK)
		{
			if(nEnable || strlen(szPrivateLAN) || strlen(szPublicLAN))
			{
				nEnable=0;
				ICS_SetShare(nEnable, szPrivateLAN, szPublicLAN);
				ICS_Reset();
				ICS_WriteConn("");
			}
		}
		//#ifdef WIN7
			if( !ICS_SetShare(1, m_OffdevName, AP_ConnPublicLAN.name))
			{
				return -2;
			}
		//#endif 
		/*#ifdef XP
			ICS_SetShare(1, m_OffdevName, AP_ConnPublicLAN.name);
			if( !RT_SetNicTcpipAddr(m_OffdevName, 0 , "192.168.159.1" , "255.255.255.0" , "" , ""))
			{
				return -1;
			}
		#endif*/	
	}
	return 0;
}

/*
把无线网卡设置成AP模式
-1:fail
0:成功
*/
int SWtoAPMode()
{
	int nLoop=5;
	while( !RT_AP_GetIsAPMode() && nLoop ) //Modify by Karl (2010/10/6)
	{
		nLoop--;
		RT_AP_SwitchToAPMode();
		Sleep(1000);
	}
	if(nLoop == 0 && RT_AP_GetIsAPMode())
		return -1;
	return 0;
}


/*
由于rtldhcp.exe持续时间只有1秒多钟  所以要保持dhcp服务需要持续调用这个函数
这个函数通常被放在一个循环中  或者 OnTimer消息中处理
*/
/*void KeepDHCP()
{
#ifdef XP
	DWORD dwProcessID;
	int	nRTLDHCP=GetProcessID2("rtldhcp.exe", dwProcessID);
	while(nRTLDHCP != 1)
	{
		CString strVV=GetAppPath()+ "RTLDHCP -v";
		WinExec(strVV , SW_HIDE);
		Sleep(1000);
		nRTLDHCP=GetProcessID2("rtldhcp.exe", dwProcessID);
	}
#endif
}*/
/*
设置网卡为client模式
*/
void SWtoNetMode()
{
	CString str="";
#ifdef WIN7
	RT_ACM_Delete_AllProfiles();
#endif
	Sleep(500);
	RT_Set_HW_PBCStatus();
	if( RT_AP_GetIsAPMode() )
	{
		RT_AP_SwitchToStationMode();
		if( g_nVersion < WWin7X86 )
		{
			ICS_DHCP_Disable(m_OffdevName);
		}
		else
		{
			char szPrivateLAN[50];
			char szPublicLAN[MAX_NAME_LEN];
			int nEnable = 0;
			memset(szPrivateLAN,0,50);
			memset(szPublicLAN,0,MAX_NAME_LEN);
			bool RetOK=ICS_GetShare(&nEnable, szPrivateLAN, szPublicLAN);
			if(RetOK)
			{
				if(nEnable || strlen(szPrivateLAN) || strlen(szPublicLAN))
				{
					nEnable=0;
					ICS_SetShare(nEnable, szPrivateLAN, szPublicLAN);
					ICS_Reset();
					ICS_WriteConn("");
				}
			}
		}
		char szNamebuf[MAX_NAME_LEN];
		char *szConnectionName=szNamebuf;
		memset(szConnectionName,0,MAX_NAME_LEN);
		if(GetConnectionName(m_OffdevName,szConnectionName))
		{
			str.Format("netsh interface ipv4  delete address \"%s\" addr=%s gateway=all",szConnectionName,AP_Use_DefaultIP);
			WinExec(str , SW_HIDE); 
		}
		str.Format("ipconfig /release \"%s\" ",szConnectionName);
		WinExec(str , SW_HIDE);
#ifdef WIN7
		RT_SetSoftAP_TcpIpAddress(m_OffdevName, 1, "", "");
#endif
		str.Format("ipconfig /renew \"%s\" ",szConnectionName);
		WinExec(str , SW_HIDE);
	}
}

bool IsWirelessAdapterUnplug(WPARAM wParam, LPARAM lParam)
{
	bool bSelectedAdapterChange = false;
	bool bIsUnplug = false;
	if( EnumDevicesChange(m_OffdevName, wParam, lParam, &bSelectedAdapterChange, &bIsUnplug) )
	{
		if(bSelectedAdapterChange && bIsUnplug)
		{
			return bIsUnplug;
		}
		
	}
	
}


BOOL RegisterDevice(HWND hWnd)
{
	HDEVNOTIFY hDevNotify;
    DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
    DWORD Err;
	
    ZeroMemory( &NotificationFilter, sizeof(NotificationFilter) );
    NotificationFilter.dbcc_size = 
        sizeof(DEV_BROADCAST_DEVICEINTERFACE);
    NotificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
	for(int i=0; i<sizeof(GUID_DEVINTERFACE_LIST)/sizeof(GUID); i++) 
	{
		NotificationFilter.dbcc_classguid = GUID_DEVINTERFACE_LIST[i];
		hDevNotify = RegisterDeviceNotification(hWnd, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);
		if(!hDevNotify) 
		{
			Err = GetLastError();
			return FALSE;
		}
	}
	
    return TRUE;
}

void FormMAC(UCHAR *src,char *dest)
{
	int i,j;
	UCHAR Hex[16]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

	j=0;
	for(i=0;i<6;i++)
	{
		dest[j++]=Hex[(src[i]&0xf0)>>4];
		dest[j++]=Hex[src[i]&0x0f];
		if(i!=5)
			dest[j++]=':';
		else
			dest[j++]=0;
	}
}

unsigned long GetStationCount()
{
	char buf[6416]={0}, SsidBuf[50]={0}, MacBuf[20]={0}, *pData=NULL;
	ULONG TotalSize,RecordSize;
	ULONGLONG ts;
	RT_AP_GetStationList(buf,6416,&TotalSize,&RecordSize,&pData,&ts);
	pAssociateEntry pEntry;
	char temp[100];
	ULONG count = 0;
	for(int i = 0;i<64;i++)
	{
		pEntry=(pAssociateEntry)(pData+i*RecordSize);
		if(pEntry->bUsed && pEntry->bAssociated)
		{
			FormMAC(pEntry->MacAddr,temp);
			printf("%d %s\n",pEntry->AID,temp);
			count++;
		}
	}
	return count;
}

void  GetAPMacAddress(char* MacBuf)
{
	RT_GetMacAddressString(MacBuf);
}


void GetSsid(char* SsidBuf)
{
	RT_GetSSID(SsidBuf);
}


static bool DetectDevice()
{
	 DEVINST     devInst;
    CONFIGRET   status;
    
    // 
    // Get the root devnode.
    // 
    
    status = CM_Locate_DevNode(&devInst, NULL, CM_LOCATE_DEVNODE_NORMAL);
    
    if (status != CR_SUCCESS) {
        printf("CM_Locate_DevNode failed: %x\n", status);
        return false;

    }
    
    status = CM_Reenumerate_DevNode(devInst, 0);
    
    if (status != CR_SUCCESS) {
        printf("CM_Reenumerate_DevNode failed: %x\n", status);
        return false;
    }

    return true;
}

bool CheckUSBPlug()
{
	DetectDevice();
	HDEVINFO hDevInfo;
    SP_DEVINFO_DATA DeviceInfoData;
    DWORD i;
	CStdioFile file;
	
	 // Create a HDEVINFO with all present devices.
    hDevInfo = SetupDiGetClassDevs(NULL,
        0, // Enumerator
        0,
        DIGCF_PRESENT | DIGCF_ALLCLASSES );
	// Enumerate through all devices in Set.
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	for (i=0;SetupDiEnumDeviceInfo(hDevInfo,i,
        &DeviceInfoData);i++)
    {
        DWORD DataT;
        LPTSTR buffer = NULL;
        DWORD buffersize = 0;
        
        // 
        // Call function with null to begin with, 
        // then use the returned buffer size 
        // to Alloc the buffer. Keep calling until
        // success or an unknown failure.
        // 
        while (!SetupDiGetDeviceRegistryProperty(
            hDevInfo,
            &DeviceInfoData,
            SPDRP_HARDWAREID,
            &DataT,
            (PBYTE)buffer,
            buffersize,
            &buffersize))
        {
            if (GetLastError() == 
                ERROR_INSUFFICIENT_BUFFER)
            {
                // Change the buffer size.
                if (buffer) LocalFree(buffer);
                buffer = (LPTSTR)LocalAlloc(LPTR,buffersize);
            }
            else
            {
                // Insert error handling here.
                break;
            }
        }

		CString str(buffer);
		CString strHWID;
		for(int c =0 ; c< g_spportHW.GetSize();c++)
		{
			strHWID = g_spportHW[c].MakeUpper();
			if(str.MakeUpper().Find(strHWID) != -1)
			{
				printf("Result:[%s]\n",buffer);
				return true;
			}
		}
        if (buffer) LocalFree(buffer);
    }
    //  Cleanup
    SetupDiDestroyDeviceInfoList(hDevInfo);
	return false;
}

int InstallDriver()
{
	CString cmdline;
	CString param;
	CString str=GetAppPath();
	CString flag = "/SE /SH /LM /SW /C /PATH ";

	int nAdapterCount=ShowDevice8180(NULL,NULL);
	if( nAdapterCount == 0)
	{
		switch(g_nVersion)
		{
		case WWin7X64:
			cmdline = "dpinst64";
			param = flag+str+"Driver\\Win7X64";
			break;

		case WWin7X86:
			cmdline = "dpinst32";
			param = flag+str+"Driver\\Win7X86";
			break;
		case WWin8X86:
			cmdline = "dpinst32";
			param = flag+str+"Driver\\Win8X86";
			break;
		case WWin8X64:
			cmdline = "dpinst64";
			param = flag+str+"Driver\\Win8X64";
			break;
		case WVistaX86:
			cmdline = "dpinst32";
			param = flag+str+"Driver\\VistaX86";
			break;
		case WVistaX64:
			cmdline = "dpinst64";
			param = flag+str+"Driver\\VistaX64";
			break;
		case WXP:
			cmdline = "dpinst32";
			param = flag+str+"Driver\\WinXP";
			break;
		case X64:
			cmdline = "dpinst64";
			param = flag+str+"Driver\\WinX64";
			break;
		}
		SHELLEXECUTEINFO ShExecInfo = {0};  
		ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);  
		ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;  
		ShExecInfo.hwnd = NULL;  
		ShExecInfo.lpVerb = NULL;  
		ShExecInfo.lpFile = cmdline;          
		ShExecInfo.lpParameters = param;     
		ShExecInfo.lpDirectory = NULL;  
		ShExecInfo.nShow = SW_HIDE;  
		ShExecInfo.hInstApp = NULL;   
		ShellExecuteEx(&ShExecInfo);  
		WaitForSingleObject(ShExecInfo.hProcess,INFINITE);
		bool bFine = false;
		for(int i=0;i<5;i++)
		{
			if( ShowDevice8180(NULL,NULL) != 0)
			{
				bFine = true;
				break;
			}
			Sleep(1000);
		}
		if( !bFine )
			return -1;
	}
	return 0;
}
