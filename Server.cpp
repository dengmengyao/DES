#include<stdio.h>
#include<string.h>
#include<WinSock2.h>
#include<time.h>
#include<string>
#include<iostream>
#include <stdlib.h>
#include "DES.h"
#pragma comment (lib,"ws2_32.lib")
using namespace std;
SOCKET sockConn;//全局变量，用来通信的socket
void recvFun();//接收信息线程
void sendFun();//发送信息线程
HANDLE h1, h2;//线程句柄
char MyKey[8] = { 'a','f','k','4','R','g','S','T' };       //初始密钥
static bool SubKey[16][48] = { 0 }; //子密钥序列

void BitsCopy(bool* BitIn, bool* BitOut, int Len) {  //BitOut 就是IP置换后的信息 
//数组复制
	int i = 0;
	for (i = 0; i < Len; i++) {
		BitOut[i] = BitIn[i];
	}
}
void TablePermute(bool* BitIn, bool* BitOut, const char* Table, int Num) {  //IP置换 
//原来的数据按对应的表上的位置进行放置
	int i = 0;
	static bool temp[256] = { 0 };
	for (i = 0; i < Num; i++) {
		temp[i] = BitIn[Table[i] - 1];
	}
	BitsCopy(temp, BitOut, Num);
}

void ByteToBit(char* ByteIn, bool* BitOut, int Num) {
	//将字节转为Byte
	int i = 0;
	for (i = 0; i < Num; i++) {
		BitOut[i] = (ByteIn[i / 8] >> (i % 8)) & 0x01;  //利用与0x01做与操作进行掩码后得到的0或1 
	}
}
void LoopMove(bool* BitIn, int Len, int Num) {    //循环左移操作 
//移位操作，注意需将左边的那1或2位移到最右边
	static bool temp[256] = { 0 };
	BitsCopy(BitIn, temp, Num);
	BitsCopy(BitIn + Num, BitIn, Len - Num);
	BitsCopy(temp, BitIn + Len - Num, Num);
}
void Getsubkey(char KeyIn[8]) {             //生成子密钥 
//通过密钥获得子密钥
	int i = 0;
	static bool KeyBit[64] = { 0 };
	static bool* KiL = &KeyBit[0], * KiR = &KeyBit[28];
	ByteToBit(KeyIn, KeyBit, 64);                    //子密钥转为bits 
	TablePermute(KeyBit, KeyBit, Subkey_Table, 56);   //子密钥压缩，舍弃每一个字符的第八位 
	for (i = 0; i < 16; i++) {                          //子密钥的高28位和低28位分别进行循环左移，左移次数看对应的Move_table表 
		LoopMove(KiL, 28, Move_Table[i]);
		LoopMove(KiR, 28, Move_Table[i]);
		TablePermute(KeyBit, SubKey[i], Compress_Table, 48); //将得到的第i个子密钥放到subKey[i]中 
	}
}

void Xor(bool* Bit1, bool* Bit2, int Num) {
	// 按位异或，存储结果在第一个里
	int i = 0;
	for (i = 0; i < Num; i++) {
		Bit1[i] = Bit1[i] ^ Bit2[i];
	}
}
void S_Change(bool BitIn[48], bool BitOut[32]) {
	// S盒变换，将48位的处理结果压缩成32位 
	int i, X, Y;
	for (i = 0, Y = 0, X = 0; i < 8; i++, BitIn += 6, BitOut += 4) {
		Y = (BitIn[0] << 1) + BitIn[5];                            //1和6位决定行数
		X = (BitIn[1] << 3) + (BitIn[2] << 2) + (BitIn[3] << 1) + BitIn[4];//2345决定列数
		ByteToBit(&S_Box[i][Y][X], BitOut, 4);
	}
}
void DES_1turn(bool BitIn[32], bool BitKi[48]) {  //右半段拓展后与子密钥进行异或 
	static bool MiR[48] = { 0 };
	TablePermute(BitIn, MiR, Ex_Table, 48);        //扩展为48位
	Xor(MiR, BitKi, 48);                          //异或操作 
	S_Change(MiR, BitIn);                        //S盒代换压缩 
	TablePermute(BitIn, BitIn, P_Box, 32);         //P置换，左半边和右半边的处理结果进行异或，然后左右交换，一轮就算完了 
}

void BitToHex(bool* BitIn, char* ByteOut, int Num) {
	//Bit转Hex
	int i = 0;
	for (i = 0; i < Num / 4; i++) {
		ByteOut[i] = 0;
	}
	for (i = 0; i < Num / 4; i++) {             //利用二进制算术运算得到的数字再转化为相应的char型 
		ByteOut[i] = BitIn[i * 4] + (BitIn[i * 4 + 1] << 1)
			+ (BitIn[i * 4 + 2] << 2) + (BitIn[i * 4 + 3] << 3);
		if ((ByteOut[i]) > 9) {
			ByteOut[i] = ByteOut[i] + '7';  //这是由于ASCII码 的数字和字母之间由六个符号的原因 
		}
		else {
			ByteOut[i] = ByteOut[i] + '0';
		}
	}
}
void BitToByte(bool* ByteIn, char* BitOut, int Num) {
	//每8次左移一位异或
	int i = 0;
	for (i = 0; i < (Num / 8); i++) {
		BitOut[i] = 0;
	}
	for (i = 0; i < Num; i++) {
		BitOut[i / 8] |= ByteIn[i] << (i % 8);
	}
}
void HexToBit(char* ByteIn, bool* BitOut, int Num) {
	//Hex转Bit
	int i = 0;
	for (i = 0; i < Num; i++) {
		if ((ByteIn[i / 4]) > '9') {
			BitOut[i] = ((ByteIn[i / 4] - '7') >> (i % 4)) & 0x01;    //又是掩码原理 
		}
		else {
			BitOut[i] = ((ByteIn[i / 4] - '0') >> (i % 4)) & 0x01;
		}
	}
}
void DES_Cry(char MesIn[8], char MesOut[8]) {
	//执行DES加密函数
	int i = 0;
	static bool MesBit[64] = { 0 };                  //信息 
	static bool Temp[32] = { 0 };                    //中间变量 
	static bool* MiL = &MesBit[0], * MiR = &MesBit[32]; //前后32位
	ByteToBit(MesIn, MesBit, 64);                   //char转bit到MesBit中 
	TablePermute(MesBit, MesBit, IP_Table, 64);      //IP置换，对信息进行错位 
	for (i = 0; i < 16; i++) {                         //16轮迭代
		BitsCopy(MiR, Temp, 32);                    //右半边复制到临时变量temp 
		DES_1turn(MiR, SubKey[i]);                 //右半边拓展和子密钥进行异或然后压缩 
		Xor(MiR, MiL, 32);                          //左右异或放到右边 
		BitsCopy(Temp, MiL, 32);                    //一开始的右边数据放到左边 
	}
	TablePermute(MesBit, MesBit, IPre_Table, 64);    //IP逆置换 
	BitToHex(MesBit, MesOut, 64);                   //以16进制输出密文 
}

void DES_Dec(char MesIn[8], char MesOut[8]) {
	//DES解密，加密的逆过程 doublesand 
	int i = 0;
	static bool MesBit[64] = { 0 };
	static bool Temp[32] = { 0 };
	static bool* MiL = &MesBit[0], * MiR = &MesBit[32];
	HexToBit(MesIn, MesBit, 64);                     //16进制密文转二进制 
	TablePermute(MesBit, MesBit, IP_Table, 64);       //IP置换 
	for (i = 15; i >= 0; i--) {                         //逆循环 
		BitsCopy(MiL, Temp, 32);                     //R(i-1) = Li, L15是密文的前半段，可以逆推 
		DES_1turn(MiL, SubKey[i]);                  //Ri = L(i-1)^f(R(i-1), K(i-1))   K(i-1)是子密钥，R15已知，根据 a = b ^ c 得 b = a^c,可以求L(i-1) 
		Xor(MiL, MiR, 32);                           //左右异或得到右边的原始信息放回左边 
		BitsCopy(Temp, MiR, 32);                     //中间变量放到右边 
	}
	TablePermute(MesBit, MesBit, IPre_Table, 64);     //IP逆置换 
	BitToByte(MesBit, MesOut, 64);                   //二进制转char 
}


int main()
{

    SOCKET serverSocket;//监视的套接字
    SOCKADDR_IN newAddr;//保存客户端的socket地址信息
    SOCKADDR_IN addr;//地址结构体，包括ip port(端口)
    WSADATA data;//存储被WSAStartup函数调用后返回的Windows Sockets数据
    WORD version;//socket版本
    int info;

    //在使用socket之前要进行版本的设定和初始化
    version = MAKEWORD(2, 2);//设定版本
    info = WSAStartup(version, &data);
    //应用程序或DLL只能在一次成功的WSAStartup()调用之后才能调用进一步的Windows Sockets API函数。
    //有套接字的接口才能进行通信


    //1.创建socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//AF_INET使用IPV4地址，SOCK_STREAM使用流传输，IPPROTO_TCP使用TCP协议
    addr.sin_addr.S_un.S_addr = htonl(ADDR_ANY);//表示任何的ip过来连接都接受
    addr.sin_family = AF_INET;//使用ipv4的地址
    addr.sin_port = htons(11111);//设定应用占用的端口


    //2.绑定socket端口号
    bind(serverSocket, (SOCKADDR*)&addr, sizeof(SOCKADDR));//将套接字serverSocket与端口接收的ip绑定
    //3.开始监听，是否有客服端请求连接,最大连接数为3
    listen(serverSocket, 3);
    cout << "开始聊天，等待对方连接.........." << endl;
    int len = sizeof(SOCKADDR);
    //accept是一个阻塞函数，如果没有客户端请求，连接会一直等待在这里
    //该函数会返回一个新的套接字，这个新的套接字是用来与客户端通信的套接字，之前那个套接字是监听的套接字
    while (1) {
        //4.接受来自客户端的连接请求
        sockConn = accept(serverSocket, (SOCKADDR*)&newAddr, &len);//接受客户端的请求
        cout << "连接成功......" << endl;
        //创建线程后立即运行
        //第一个参数表示线程内核对象的安全属性；第二个参数表示线程栈空间大小；第三个参数表示新线程所执行的线程函数地址（函数的名字），多个线程可以使用同一个函数地址
        //第四个参数是传递给线程函数的参数；第五个参数指定什么时候调用线程，为0表示线程创建之后就可以进行调用；第六个参数返回线程的ID号，传入NULL表示不需要返回该线程ID号
        //5.向socket中读取/写入信息
        h1 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sendFun, NULL, 0, NULL);//用于发送的线程
        h2 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)recvFun, NULL, 0, NULL);//用于接收的线程
    }
    //6.关闭
    closesocket(sockConn);//关闭套接字
    return 0;
}
void sendFun()
{
	char buf[128];
	while (1)
	{
		char buf1[64];
		cout << "请输入消息:";
		cin >> buf1;
		if (strcmp(buf1, "bye!") == 0) {
			cout << "聊天已结束!" << endl;
			char buf0[64] = "End";
			strcpy(buf1, buf0);   //加密过程
		}//判断聊天结束
		for (int i = 0; i < 8; i++) {
			char MesHex[16];     //存放密文
			char buf_part[8];
			for (int j = 0; j < 8; j++)
				buf_part[j] = buf1[8 * i + j];
			DES_Cry(buf_part, MesHex);   //加密过程 
			for (int k = 0; k < 16; k++)
				buf[16*i+k]=MesHex[k];
		}
		cout << "发送消息,加密后消息密文如下:";
		for (int i = 0; i < 128; i++)
			cout << buf[i];
		cout << endl;
		//发送数据
		send(sockConn, buf,128, 0);
	}
}

void recvFun()
{
    char buf[128];
    while (1)
    {
        int Ret = recv(sockConn, buf, 128, 0);//接收信息
		cout << "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";
		cout << "收到的密文如下所示：";
		for (int i = 0; i < 128; i++)
			cout << buf[i];
		cout << endl;
		char MyMessage[64];
		for (int i = 0; i < 8; i++) {
			char buf_part[16];
			char MyMessage_part[8];
			for (int j = 0; j < 16; j++)
				buf_part[j] = buf[i * 16 + j];
			DES_Dec(buf_part, MyMessage_part);  //解密过程
			for (int k = 0; k < 8; k++)
				MyMessage[8 * i + k] = MyMessage_part[k];
		}
        if (Ret < 0) {
            cout << "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";
            cout << "对方已退出!" << endl;
            break;
        }
        else if (Ret == 0) {
            cout << "ERROR_RECV";
        }
        else if (strcmp(MyMessage, "End") == 0) {//若收到send发出的End,则结束聊天
            cout << "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";
            cout << "对方已结束聊天" << endl;
            break;
        }
        else {
            cout << "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";
            cout << "接收到的消息解密后具体信息如下:" ;
			for (int i = 0; i < 64; i++) {
				int u = MyMessage[i];
				if (u != -52)
					cout << MyMessage[i];
			}
			cout << endl;
            cout <<  "请输入消息:";

        }
    }
}

