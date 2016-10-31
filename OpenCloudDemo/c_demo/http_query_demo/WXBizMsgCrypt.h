
#pragma once

#include <string>
#include <stdint.h>
//#include "tinyxml2/tinyxml2.h"

namespace EncryptAndDecrypt {

static const unsigned int kAesKeySize = 32;
static const unsigned int kAesIVSize = 16;
static const unsigned int kEncodingKeySize = 16;//43;
static const unsigned int kRandEncryptStrLen = 16;
static const unsigned int kMsgLen = 4;
static const unsigned int kMaxBase64Size = 1000000000;
enum  WXBizMsgCryptErrorCode
{
    WXBizMsgCrypt_OK = 0,
    WXBizMsgCrypt_ValidateSignature_Error = -40001,
    WXBizMsgCrypt_ParseXml_Error = -40002,
    WXBizMsgCrypt_ComputeSignature_Error = -40003,
    WXBizMsgCrypt_IllegalAesKey = -40004,
    WXBizMsgCrypt_ValidateAppid_Error = -40005,
    WXBizMsgCrypt_EncryptAES_Error = -40006,
    WXBizMsgCrypt_DecryptAES_Error = -40007,
    WXBizMsgCrypt_IllegalBuffer = -40008,
    WXBizMsgCrypt_EncodeBase64_Error = -40009,
    WXBizMsgCrypt_DecodeBase64_Error = -40010,
    WXBizMsgCrypt_GenReturnXml_Error = -40011,
};

class WXBizMsgCrypt
{
public:
    //构造函数
    // @param sEncodingAESKey: 设置的EncodingAESKey
    WXBizMsgCrypt(const std::string &sEncodingAESKey)
                    :m_sEncodingAESKey(sEncodingAESKey)
                    {   }
    
    // @param sEncryptData: 密文，对应POST请求的数据
    // @param sMsg: 解密后的原文，当return返回0时有效
    // @return: 成功0，失败返回对应的错误码
    int DecryptMsg(const std::string &sPostData,
                    std::string &sMsg);
            
            
    //将公众号回复用户的消息加密打包
    // @param sOrgMsg:待加密字符串
    // @param sEncryptMsg: 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串,
    //                      当return返回0时有效
    // return：成功0，失败返回对应的错误码
    int EncryptMsg(const std::string &sOrgMsg,
                    std::string &sEncryptMsg);
private:
    std::string m_sEncodingAESKey;

private:
    // AES CBC
    int AES_CBCEncrypt( const char * sSource, const uint32_t iSize,
            const char * sKey, unsigned int iKeySize, std::string * poResult );
    
    int AES_CBCEncrypt( const std::string & objSource,
            const std::string & objKey, std::string * poResult );
    
    int AES_CBCDecrypt( const char * sSource, const uint32_t iSize,
            const char * sKey, uint32_t iKeySize, std::string * poResult );
    
    int AES_CBCDecrypt( const std::string & objSource,
            const std::string & objKey, std::string * poResult );
    
    //base64
    int EncodeBase64(const std::string sSrc, std::string & sTarget);
    
    int DecodeBase64(const std::string sSrc, std::string & sTarget);

};

}

