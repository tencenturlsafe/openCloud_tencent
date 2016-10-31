#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <string>
#include <sys/time.h>
#include <sstream>
#include "udp_query.pb.h"
#include <openssl/md5.h>
#include "WXBizMsgCrypt.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>

using namespace std;
using namespace url_open_query;
using namespace EncryptAndDecrypt;

string getSignFromTimeStampKey(unsigned int uiTimeStamp, string strKey)
{
	std::ostringstream oStream;
	oStream << uiTimeStamp << strKey;
	string strTsKey = oStream.str();

	fprintf(stderr, "strTsKey:%s\n", strTsKey.c_str());
	unsigned char md[16];
	MD5((unsigned char *) strTsKey.c_str(), strTsKey.length(), md);

	string strResult;
	char tmp[3];
	for (int i = 8; i < 16; i++)
	{
		sprintf(tmp, "%02x", md[i]);
		strResult.append(tmp);
	}
	fprintf(stderr, "sign:%s\n", strResult.c_str());

	return strResult;
}
struct in_addr* GetIpByHost(const char* pszHost, char *pszIp, int iMaxLen)
{
	struct hostent * host_addr = gethostbyname(pszHost);
	if (host_addr == NULL)
	{
		return 0;
	}

	struct in_addr *in = (struct in_addr *) host_addr->h_addr;

	if (pszIp != NULL)
	{
		char *sIp = inet_ntoa(*in);
		strncpy(pszIp, sIp, iMaxLen);
	}
	return in;
}
static int isValidIPAddr(char *sIP)
{
	u_int32_t uiIpAddress;
	if (NULL == sIP)
		return 0;

	if (strlen(sIP) < 7 || strlen(sIP) > 15)
		return 0;

	uiIpAddress = inet_addr(sIP);
	if (uiIpAddress == INADDR_NONE || uiIpAddress == INADDR_ANY)
		return 0;
	return 1;
}

#define UDP_PORT 15113 

int main(int argc, char *argv[])
{
	char sServerIP[16] ={ 0 };
	int16_t nServerPort = 0;
	if (argc != 7)
	{
		fprintf(stderr, "Usage: bin url host appid key port version(1.0 or 2.o)\n");
		exit(-1);
	}

	if (0 == isValidIPAddr(argv[2]))
	{
		char szDestIp[20] = { 0 };
		GetIpByHost(argv[2], szDestIp, sizeof(szDestIp));
		printf("dest ip:%s\n", szDestIp);
		strncpy(sServerIP, szDestIp, 16);
	}
	else
	{
		strncpy(sServerIP, argv[2], 16);
	}
	printf("dest ip:%s\n", sServerIP);

	nServerPort = atoi(argv[5]);

	int sockfd;
	struct sockaddr_in servaddr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	size_t isize = sizeof(struct sockaddr_in);
	memset((void*) &servaddr, 0, isize);
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(nServerPort);

	int ret = inet_pton(AF_INET, sServerIP, &(servaddr.sin_addr));
	if (ret <= 0)
	{
		printf("CreatSrvAddr(): server IP is invalid!, ret:%d \n", ret);
		return -1;
	}

	string strKey = argv[4];
	// compose package
	unsigned int uiCurrTs = time(NULL);
	string strSign = getSignFromTimeStampKey(uiCurrTs, strKey);
	string strEchoStr = "0123456789012345";
	string strv = argv[6];

	UdpQueryReq oReq;
	UdpQueryReq_Header* pHead = oReq.mutable_header();
	pHead->set_v(strv);
	pHead->set_time(uiCurrTs);
/*
	cout<<"time=:"<<pHead->time()<<endl;
	cout<<"strKey=:"<<strKey<<endl;
	cout<<"sign=:"<<strSign<<endl;
*/
	pHead->set_appid(atoi(argv[3]));
	pHead->set_echostr(strEchoStr);
	pHead->set_sign(strSign);

	UdpQueryReq_ReqInfo oReqInfo;
	oReqInfo.set_id(1);
	oReqInfo.set_url(argv[1]);
	oReqInfo.set_deviceid("TEST_TENCENT");

	string strReqInfo;
	bool bRet = oReqInfo.SerializeToString(&strReqInfo);
	if (!bRet)
	{
		fprintf(stderr, "oReqInfo.SerializeToArray Fail\n");
		return -1;
	}

	WXBizMsgCrypt crypt(strKey);
	string strEcryptReqInfo;
	crypt.EncryptMsg(strReqInfo, strEcryptReqInfo);
	oReq.set_reqinfo(strEcryptReqInfo);

	string strSendBuffer;
	bRet = oReq.SerializeToString(&strSendBuffer);
	if (!bRet)
	{
		fprintf(stderr, "oReq.SerializeToString");
		return -1;
	}

	//set timeout
	struct timeval timeout =
	{ 1, 0 };
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))
			== -1)
	{
		printf("setsockopt() error\n");
		return -1;
	}

	char recvBuffer[2048];
	UdpQueryRsp oRsp;
	//send req
	//	for(int i=0;i<2000000;i++)
	{
		int iRet = sendto(sockfd, strSendBuffer.c_str(), strSendBuffer.length(), 0,
				(sockaddr *) &servaddr, sizeof(servaddr));
		/*
		   cout<<"iRet = "<<iRet<<endl;
		   cout<<"sendbuff = "<<strSendBuffer<<endl;
		   */
		//recv resp
		int iRetLen = recvfrom(sockfd, recvBuffer, sizeof(recvBuffer), 0, NULL,
				NULL);
		if (iRetLen <= 0)
		{
			printf("recvfrom error\n");
			//continue;
			//return -1;
		}


		string recvStr;
		string recvtmp = recvBuffer;
		if(strv == "2.0" || strv == "2")
		{
			crypt.DecryptMsg(recvtmp,recvStr);
			oRsp.ParseFromArray(recvStr.c_str(), recvStr.size());
			//cout<<"urlclass:"<<oRsp.infos().urlclass()
			//	<<"urlsubclass:"<<oRsp.infos().urlsubclass()<<endl;
		}
		else
		{
			oRsp.ParseFromArray(recvBuffer, iRetLen);
		}
		//if(i==1)
		{
			printf("status:%d\n"
					"msg:%s\n"
					"echostr:%s\n"
					"id:%d\n"
					"url:%s\n"
					"urltype:%d\n"
					"eviltype:%d\n"
					"evilclass:%d\n", oRsp.status(), oRsp.msg().c_str(),
					oRsp.echostr().c_str(), oRsp.infos().id(),
					oRsp.infos().url().c_str(), oRsp.infos().urltype(),
					oRsp.infos().eviltype(),oRsp.infos().evilclass());
		}

	}
	return 0;
}
