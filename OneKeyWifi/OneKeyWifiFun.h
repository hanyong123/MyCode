#pragma  once

//#define XP 1              //����XP��ʱ����
#define WIN7 1         //����WIN7 WIN8 VISTA��ʱ����



/*
���USB���������Ƿ����,�����Ƿ�װ����
����true ����
����false û�в���
*/
bool CheckUSBPlug();

/*
��װ����-1��װʧ��
0��װ�ɹ�
*/
int InstallDriver();
/*
��ʼ��ģ�飬Ҫʹ��ģ���������������ȵ����������
����:
-1:GetWinVer fail
0:�ɹ�
*/
int OneKeyWifiInit();



/*
�ҵ�������������ʼ�����ڵ���OneKeyWifiInit�� ������������֮ǰ Ҫ�ȵ����������
�������Ҳ���������ж����������Ƿ�γ�
0:�ɹ�
-1���Ҳ�����������
-2����ʼ����������ʧ��
*/
int FindAndInitDevice();



/*
�������������ó�APģʽ
-1:fail
0:�ɹ�
*/
int SWtoAPMode();



/*
����AP�Ĳ����������������ʱ�������봦��APģʽ������˵SWtoAPMode���óɹ�
-1:PasswordHash fail
-2:RT_AP_SetPassphrase fail
0:�ɹ�
*/
int ConfigVAP(CString& ssid,const char *PassWord,bool bHidssid=false);



/*
�Զ�����ϵͳ��internet����
-1:Get_Hi_Speed_Adapter fail
-2:ICS_SetShare fail
0:�ɹ�
*/
int AutoSetICS();




/*
����rtldhcp.exe����ʱ��ֻ��1�����  ����Ҫ����dhcp������Ҫ���������������
�������ͨ��������һ��ѭ����  ���� OnTimer��Ϣ�д���
*/
//void KeepDHCP();




/*
��������Ϊclientģʽ
*/
void SWtoNetMode();

/*
ע���豸��Ϣ  �����豸��Ϣ  �ж������Ƿ�γ�  Ҫ��ע����������Ϣ
*/
BOOL RegisterDevice(HWND hWnd);

/*
��WM_DEVICECHANGE��Ϣ�� �ж����������Ƿ�γ�
*/
bool IsWirelessAdapterUnplug(WPARAM wParam, LPARAM lParam);

/*
�õ��ͻ�������
*/
unsigned long GetStationCount();



//�õ�AP mac��ַ
void  GetAPMacAddress(char* MacBuf);


//�õ� AP SSID
void GetSsid(char* SsidBuf);

