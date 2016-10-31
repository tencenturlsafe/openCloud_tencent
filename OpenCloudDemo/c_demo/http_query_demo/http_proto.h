/*
 * http_post.h
 *
 *  Created on: 2012-5-1
 *      Author: tosneytao
 *  Modify on: 2015-11-12 by julieyjzhu, update recv http method
 */

#ifndef HTTP_POST_H_
#define HTTP_POST_H_

#include <iostream>
#include <string>
#include <stdlib.h>
#include <assert.h>
#include <netdb.h>



int HttpPostRequest (const char* pszHost, unsigned short port, const char* pszFilePath, const char* pszParam, std::string& strRespHeader, std::string& strRespBody);

#endif /* HTTP_POST_H_ */
