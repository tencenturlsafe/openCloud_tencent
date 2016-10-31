/*
 * http_post.cpp
 *
 *  Created on: 2012-5-1
 *      Author: tosneytao
 *  Modify on: 2015-11-12 by julieyjzhu, update recv http method
 *
 */

#include <stdio.h>
#include <string.h>
#include "http_proto.h"

#define SEND_HTTP_REQUEST(msg) send(fd,msg,strlen(msg),0);


static int SendPostRequest(int fd, const char* pszHost, const char* pszFilePath, const char* pszParam)
{
	/*
	   POST / HTTP/1.0
	Connection: Keep-Alive
	Content-length: 209
	Content-type: text/plain
	Host: urlopen.kf0309.3g.qq.com
	User-Agent: ApacheBench/2.3
	Accept: 
	*/
	SEND_HTTP_REQUEST("POST ");
	SEND_HTTP_REQUEST(pszFilePath);
	SEND_HTTP_REQUEST(" HTTP/1.0\r\n");
	SEND_HTTP_REQUEST("Accept: */*\r\n");
	//SEND_HTTP_REQUEST("User-Agent: Mozilla/4.0\r\n");

	char szContentHeader[100];
	sprintf(szContentHeader,"Content-Length: %d\r\n",strlen(pszParam));
	SEND_HTTP_REQUEST(szContentHeader);
	SEND_HTTP_REQUEST("Accept-Encoding: gzip, deflate\r\n");
	SEND_HTTP_REQUEST("Host: ");
	SEND_HTTP_REQUEST(pszHost);
	SEND_HTTP_REQUEST("\r\n");
	SEND_HTTP_REQUEST("Content-Type: application/x-www-form-urlencoded\r\n");
	SEND_HTTP_REQUEST("Connection: Keep-Alive\r\n");

	SEND_HTTP_REQUEST("\r\n");
	SEND_HTTP_REQUEST(pszParam);


	return 0;
}


static int GetHTTPResponse(int fd, std::string& strRespHeader, std::string& strRespBody)
{
	char szRecv[1];
	int iRecvLen;
	bool isEnd = false;
	bool bStatusOK = false;
	int iContentLen = 0;


	// recv header
	strRespHeader.clear();
	while(!isEnd)
	{

		iRecvLen = recv(fd, szRecv, 1, 0);
		if(iRecvLen<0)
		{
			isEnd = true;
		}

		strRespHeader +=szRecv[0];
		if(szRecv[0]=='\n')
		{
			if(strRespHeader.find("\r\n\r\n") != std::string::npos)
			{
				isEnd = true;
			}
		}
	}



	// check response ok
	if(strRespHeader.find("200 OK\r\n") != std::string::npos)
	{

		bStatusOK = true;
	}

	if(!bStatusOK)
	{
		return -1;
	}

	// get length of content
	std::string::size_type  bpos = strRespHeader.find("Content-Length:");
	if(bpos != std::string::npos)
	{
		std::string temp = strRespHeader.substr(bpos+15);
		std::string::size_type  epos = strRespHeader.find("\r\n");
		if(epos != std::string::npos)
		{
			std::string contentlen = temp.substr(0, epos);
			iContentLen = atoi(contentlen.c_str());
		}

	}

	//printf("content-length:%d\n", iContentLen);

	// get body
	int irecv = 0;
	strRespBody.clear();
	while(irecv < iContentLen)
	{
		iRecvLen = recv(fd, szRecv, 1, 0);
		if(iRecvLen<0)
		{
			break;
		}
		irecv ++;
		strRespBody+=szRecv[0];
	}

	return 0;
}

int HttpPostRequest (const char* pszHost, unsigned short port,
		const char* pszFilePath, const char* pszParam,
		std::string& strRespHeader, std::string& strRespBody)
{

	sockaddr_in       sin;
	int sock = socket (AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	{
		printf("sock error\n");
		return -100;
	}
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	struct hostent * host_addr = gethostbyname(pszHost);
	if(host_addr==NULL)
	{
		printf("host_addr error\n");
		close(sock);
		return -103;
	}
	sin.sin_addr.s_addr = *((int*)*host_addr->h_addr_list) ;
	int iRet = 0;
	if((iRet =connect (sock,(const struct sockaddr *)&sin, sizeof(sockaddr_in) )) == -1 )
	{
		perror("connect error");
		printf("connect error,\n");
		close(sock);
		return -101;
	}

	//for(int iiii=0;iiii<2000000;iiii++)
	//	    for(int i=0;i<2000;i++)
	{
		SendPostRequest(sock, pszHost, pszFilePath, pszParam);

		GetHTTPResponse(sock, strRespHeader, strRespBody);
	}
	close(sock);

	return 0;
}




