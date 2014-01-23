#pragma  once

//#define XP 1              //编译XP的时候定义
#define WIN7 1         //编译WIN7 WIN8 VISTA的时候定义



/*
检查USB无线网卡是否插入,无论是否安装驱动
返回true 插入
返回false 没有插入
*/
bool CheckUSBPlug();

/*
安装驱动-1安装失败
0安装成功
*/
int InstallDriver();
/*
初始化模块，要使用模块其他函数必须先调用这个函数
返回:
-1:GetWinVer fail
0:成功
*/
int OneKeyWifiInit();



/*
找到无线网卡并初始化，在调用OneKeyWifiInit后 调用其他函数之前 要先调用这个函数
这个函数也可以用于判断无线网卡是否拔出
0:成功
-1：找不到无线网卡
-2：初始化无线网卡失败
*/
int FindAndInitDevice();



/*
把无线网卡设置成AP模式
-1:fail
0:成功
*/
int SWtoAPMode();



/*
配置AP的参数，调用这个函数时网卡必须处于AP模式，就是说SWtoAPMode调用成功
-1:PasswordHash fail
-2:RT_AP_SetPassphrase fail
0:成功
*/
int ConfigVAP(CString& ssid,const char *PassWord,bool bHidssid=false);



/*
自动设置系统的internet共享
-1:Get_Hi_Speed_Adapter fail
-2:ICS_SetShare fail
0:成功
*/
int AutoSetICS();




/*
由于rtldhcp.exe持续时间只有1秒多钟  所以要保持dhcp服务需要持续调用这个函数
这个函数通常被放在一个循环中  或者 OnTimer消息中处理
*/
//void KeepDHCP();




/*
设置网卡为client模式
*/
void SWtoNetMode();

/*
注册设备消息  监听设备消息  判断网卡是否拔出  要先注册网卡的消息
*/
BOOL RegisterDevice(HWND hWnd);

/*
在WM_DEVICECHANGE消息中 判断无线网卡是否拔出
*/
bool IsWirelessAdapterUnplug(WPARAM wParam, LPARAM lParam);

/*
得到客户端数量
*/
unsigned long GetStationCount();



//得到AP mac地址
void  GetAPMacAddress(char* MacBuf);


//得到 AP SSID
void GetSsid(char* SsidBuf);

