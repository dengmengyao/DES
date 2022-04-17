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
SOCKET sockConn;//ȫ�ֱ���������ͨ�ŵ�socket
void recvFun();//������Ϣ�߳�
void sendFun();//������Ϣ�߳�
HANDLE h1, h2;//�߳̾��
char MyKey[8] = { 'a','f','k','4','R','g','S','T' };       //��ʼ��Կ
static bool SubKey[16][48] = { 0 }; //����Կ����

void BitsCopy(bool* BitIn, bool* BitOut, int Len) {  //BitOut ����IP�û������Ϣ 
//���鸴��
	int i = 0;
	for (i = 0; i < Len; i++) {
		BitOut[i] = BitIn[i];
	}
}
void TablePermute(bool* BitIn, bool* BitOut, const char* Table, int Num) {  //IP�û� 
//ԭ�������ݰ���Ӧ�ı��ϵ�λ�ý��з���
	int i = 0;
	static bool temp[256] = { 0 };
	for (i = 0; i < Num; i++) {
		temp[i] = BitIn[Table[i] - 1];
	}
	BitsCopy(temp, BitOut, Num);
}

void ByteToBit(char* ByteIn, bool* BitOut, int Num) {
	//���ֽ�תΪByte
	int i = 0;
	for (i = 0; i < Num; i++) {
		BitOut[i] = (ByteIn[i / 8] >> (i % 8)) & 0x01;  //������0x01����������������õ���0��1 
	}
}
void LoopMove(bool* BitIn, int Len, int Num) {    //ѭ�����Ʋ��� 
//��λ������ע���轫��ߵ���1��2λ�Ƶ����ұ�
	static bool temp[256] = { 0 };
	BitsCopy(BitIn, temp, Num);
	BitsCopy(BitIn + Num, BitIn, Len - Num);
	BitsCopy(temp, BitIn + Len - Num, Num);
}
void Getsubkey(char KeyIn[8]) {             //��������Կ 
//ͨ����Կ�������Կ
	int i = 0;
	static bool KeyBit[64] = { 0 };
	static bool* KiL = &KeyBit[0], * KiR = &KeyBit[28];
	ByteToBit(KeyIn, KeyBit, 64);                    //����ԿתΪbits 
	TablePermute(KeyBit, KeyBit, Subkey_Table, 56);   //����Կѹ��������ÿһ���ַ��ĵڰ�λ 
	for (i = 0; i < 16; i++) {                          //����Կ�ĸ�28λ�͵�28λ�ֱ����ѭ�����ƣ����ƴ�������Ӧ��Move_table�� 
		LoopMove(KiL, 28, Move_Table[i]);
		LoopMove(KiR, 28, Move_Table[i]);
		TablePermute(KeyBit, SubKey[i], Compress_Table, 48); //���õ��ĵ�i������Կ�ŵ�subKey[i]�� 
	}
}

void Xor(bool* Bit1, bool* Bit2, int Num) {
	// ��λ��򣬴洢����ڵ�һ����
	int i = 0;
	for (i = 0; i < Num; i++) {
		Bit1[i] = Bit1[i] ^ Bit2[i];
	}
}
void S_Change(bool BitIn[48], bool BitOut[32]) {
	// S�б任����48λ�Ĵ�����ѹ����32λ 
	int i, X, Y;
	for (i = 0, Y = 0, X = 0; i < 8; i++, BitIn += 6, BitOut += 4) {
		Y = (BitIn[0] << 1) + BitIn[5];                            //1��6λ��������
		X = (BitIn[1] << 3) + (BitIn[2] << 2) + (BitIn[3] << 1) + BitIn[4];//2345��������
		ByteToBit(&S_Box[i][Y][X], BitOut, 4);
	}
}
void DES_1turn(bool BitIn[32], bool BitKi[48]) {  //�Ұ����չ��������Կ������� 
	static bool MiR[48] = { 0 };
	TablePermute(BitIn, MiR, Ex_Table, 48);        //��չΪ48λ
	Xor(MiR, BitKi, 48);                          //������ 
	S_Change(MiR, BitIn);                        //S�д���ѹ�� 
	TablePermute(BitIn, BitIn, P_Box, 32);         //P�û������ߺ��Ұ�ߵĴ������������Ȼ�����ҽ�����һ�־������� 
}

void BitToHex(bool* BitIn, char* ByteOut, int Num) {
	//BitתHex
	int i = 0;
	for (i = 0; i < Num / 4; i++) {
		ByteOut[i] = 0;
	}
	for (i = 0; i < Num / 4; i++) {             //���ö�������������õ���������ת��Ϊ��Ӧ��char�� 
		ByteOut[i] = BitIn[i * 4] + (BitIn[i * 4 + 1] << 1)
			+ (BitIn[i * 4 + 2] << 2) + (BitIn[i * 4 + 3] << 3);
		if ((ByteOut[i]) > 9) {
			ByteOut[i] = ByteOut[i] + '7';  //��������ASCII�� �����ֺ���ĸ֮�����������ŵ�ԭ�� 
		}
		else {
			ByteOut[i] = ByteOut[i] + '0';
		}
	}
}
void BitToByte(bool* ByteIn, char* BitOut, int Num) {
	//ÿ8������һλ���
	int i = 0;
	for (i = 0; i < (Num / 8); i++) {
		BitOut[i] = 0;
	}
	for (i = 0; i < Num; i++) {
		BitOut[i / 8] |= ByteIn[i] << (i % 8);
	}
}
void HexToBit(char* ByteIn, bool* BitOut, int Num) {
	//HexתBit
	int i = 0;
	for (i = 0; i < Num; i++) {
		if ((ByteIn[i / 4]) > '9') {
			BitOut[i] = ((ByteIn[i / 4] - '7') >> (i % 4)) & 0x01;    //��������ԭ�� 
		}
		else {
			BitOut[i] = ((ByteIn[i / 4] - '0') >> (i % 4)) & 0x01;
		}
	}
}
void DES_Cry(char MesIn[8], char MesOut[8]) {
	//ִ��DES���ܺ���
	int i = 0;
	static bool MesBit[64] = { 0 };                  //��Ϣ 
	static bool Temp[32] = { 0 };                    //�м���� 
	static bool* MiL = &MesBit[0], * MiR = &MesBit[32]; //ǰ��32λ
	ByteToBit(MesIn, MesBit, 64);                   //charתbit��MesBit�� 
	TablePermute(MesBit, MesBit, IP_Table, 64);      //IP�û�������Ϣ���д�λ 
	for (i = 0; i < 16; i++) {                         //16�ֵ���
		BitsCopy(MiR, Temp, 32);                    //�Ұ�߸��Ƶ���ʱ����temp 
		DES_1turn(MiR, SubKey[i]);                 //�Ұ����չ������Կ�������Ȼ��ѹ�� 
		Xor(MiR, MiL, 32);                          //�������ŵ��ұ� 
		BitsCopy(Temp, MiL, 32);                    //һ��ʼ���ұ����ݷŵ���� 
	}
	TablePermute(MesBit, MesBit, IPre_Table, 64);    //IP���û� 
	BitToHex(MesBit, MesOut, 64);                   //��16����������� 
}

void DES_Dec(char MesIn[8], char MesOut[8]) {
	//DES���ܣ����ܵ������ doublesand 
	int i = 0;
	static bool MesBit[64] = { 0 };
	static bool Temp[32] = { 0 };
	static bool* MiL = &MesBit[0], * MiR = &MesBit[32];
	HexToBit(MesIn, MesBit, 64);                     //16��������ת������ 
	TablePermute(MesBit, MesBit, IP_Table, 64);       //IP�û� 
	for (i = 15; i >= 0; i--) {                         //��ѭ�� 
		BitsCopy(MiL, Temp, 32);                     //R(i-1) = Li, L15�����ĵ�ǰ��Σ��������� 
		DES_1turn(MiL, SubKey[i]);                  //Ri = L(i-1)^f(R(i-1), K(i-1))   K(i-1)������Կ��R15��֪������ a = b ^ c �� b = a^c,������L(i-1) 
		Xor(MiL, MiR, 32);                           //�������õ��ұߵ�ԭʼ��Ϣ�Ż���� 
		BitsCopy(Temp, MiR, 32);                     //�м�����ŵ��ұ� 
	}
	TablePermute(MesBit, MesBit, IPre_Table, 64);     //IP���û� 
	BitToByte(MesBit, MesOut, 64);                   //������תchar 
}


int main()
{

    SOCKET serverSocket;//���ӵ��׽���
    SOCKADDR_IN newAddr;//����ͻ��˵�socket��ַ��Ϣ
    SOCKADDR_IN addr;//��ַ�ṹ�壬����ip port(�˿�)
    WSADATA data;//�洢��WSAStartup�������ú󷵻ص�Windows Sockets����
    WORD version;//socket�汾
    int info;

    //��ʹ��socket֮ǰҪ���а汾���趨�ͳ�ʼ��
    version = MAKEWORD(2, 2);//�趨�汾
    info = WSAStartup(version, &data);
    //Ӧ�ó����DLLֻ����һ�γɹ���WSAStartup()����֮����ܵ��ý�һ����Windows Sockets API������
    //���׽��ֵĽӿڲ��ܽ���ͨ��


    //1.����socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//AF_INETʹ��IPV4��ַ��SOCK_STREAMʹ�������䣬IPPROTO_TCPʹ��TCPЭ��
    addr.sin_addr.S_un.S_addr = htonl(ADDR_ANY);//��ʾ�κε�ip�������Ӷ�����
    addr.sin_family = AF_INET;//ʹ��ipv4�ĵ�ַ
    addr.sin_port = htons(11111);//�趨Ӧ��ռ�õĶ˿�


    //2.��socket�˿ں�
    bind(serverSocket, (SOCKADDR*)&addr, sizeof(SOCKADDR));//���׽���serverSocket��˿ڽ��յ�ip��
    //3.��ʼ�������Ƿ��пͷ�����������,���������Ϊ3
    listen(serverSocket, 3);
    cout << "��ʼ���죬�ȴ��Է�����.........." << endl;
    int len = sizeof(SOCKADDR);
    //accept��һ���������������û�пͻ����������ӻ�һֱ�ȴ�������
    //�ú����᷵��һ���µ��׽��֣�����µ��׽�����������ͻ���ͨ�ŵ��׽��֣�֮ǰ�Ǹ��׽����Ǽ������׽���
    while (1) {
        //4.�������Կͻ��˵���������
        sockConn = accept(serverSocket, (SOCKADDR*)&newAddr, &len);//���ܿͻ��˵�����
        cout << "���ӳɹ�......" << endl;
        //�����̺߳���������
        //��һ��������ʾ�߳��ں˶���İ�ȫ���ԣ��ڶ���������ʾ�߳�ջ�ռ��С��������������ʾ���߳���ִ�е��̺߳�����ַ�����������֣�������߳̿���ʹ��ͬһ��������ַ
        //���ĸ������Ǵ��ݸ��̺߳����Ĳ��������������ָ��ʲôʱ������̣߳�Ϊ0��ʾ�̴߳���֮��Ϳ��Խ��е��ã����������������̵߳�ID�ţ�����NULL��ʾ����Ҫ���ظ��߳�ID��
        //5.��socket�ж�ȡ/д����Ϣ
        h1 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sendFun, NULL, 0, NULL);//���ڷ��͵��߳�
        h2 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)recvFun, NULL, 0, NULL);//���ڽ��յ��߳�
    }
    //6.�ر�
    closesocket(sockConn);//�ر��׽���
    return 0;
}
void sendFun()
{
	char buf[128];
	while (1)
	{
		char buf1[64];
		cout << "��������Ϣ:";
		cin >> buf1;
		if (strcmp(buf1, "bye!") == 0) {
			cout << "�����ѽ���!" << endl;
			char buf0[64] = "End";
			strcpy(buf1, buf0);   //���ܹ���
		}//�ж��������
		for (int i = 0; i < 8; i++) {
			char MesHex[16];     //�������
			char buf_part[8];
			for (int j = 0; j < 8; j++)
				buf_part[j] = buf1[8 * i + j];
			DES_Cry(buf_part, MesHex);   //���ܹ��� 
			for (int k = 0; k < 16; k++)
				buf[16*i+k]=MesHex[k];
		}
		cout << "������Ϣ,���ܺ���Ϣ��������:";
		for (int i = 0; i < 128; i++)
			cout << buf[i];
		cout << endl;
		//��������
		send(sockConn, buf,128, 0);
	}
}

void recvFun()
{
    char buf[128];
    while (1)
    {
        int Ret = recv(sockConn, buf, 128, 0);//������Ϣ
		cout << "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";
		cout << "�յ�������������ʾ��";
		for (int i = 0; i < 128; i++)
			cout << buf[i];
		cout << endl;
		char MyMessage[64];
		for (int i = 0; i < 8; i++) {
			char buf_part[16];
			char MyMessage_part[8];
			for (int j = 0; j < 16; j++)
				buf_part[j] = buf[i * 16 + j];
			DES_Dec(buf_part, MyMessage_part);  //���ܹ���
			for (int k = 0; k < 8; k++)
				MyMessage[8 * i + k] = MyMessage_part[k];
		}
        if (Ret < 0) {
            cout << "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";
            cout << "�Է����˳�!" << endl;
            break;
        }
        else if (Ret == 0) {
            cout << "ERROR_RECV";
        }
        else if (strcmp(MyMessage, "End") == 0) {//���յ�send������End,���������
            cout << "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";
            cout << "�Է��ѽ�������" << endl;
            break;
        }
        else {
            cout << "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b";
            cout << "���յ�����Ϣ���ܺ������Ϣ����:" ;
			for (int i = 0; i < 64; i++) {
				int u = MyMessage[i];
				if (u != -52)
					cout << MyMessage[i];
			}
			cout << endl;
            cout <<  "��������Ϣ:";

        }
    }
}

