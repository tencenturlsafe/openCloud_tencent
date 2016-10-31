
#include "WXBizMsgCrypt.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

#include "openssl/aes.h"
#include "openssl/sha.h"
#include "openssl/evp.h"


#define FREE_PTR(ptr) \
    if (NULL != (ptr)) {\
        free (ptr);\
        (ptr) = NULL;\
    }

#define DELETE_PTR(ptr) \
    if (NULL != (ptr)) {\
        delete (ptr);\
        (ptr) = NULL;\
    }
    
namespace EncryptAndDecrypt{

int WXBizMsgCrypt::DecryptMsg(const std::string &sEncryptMsg,
                std::string &sMsg)
{
    //1.decode base64
    std::string sAesData;
    if(0 != DecodeBase64(sEncryptMsg,sAesData))
    {
        return WXBizMsgCrypt_DecodeBase64_Error;
    }
    
    //2.decode aes
    std::string sNoEncryptData;
    if(0 != AES_CBCDecrypt(sAesData, m_sEncodingAESKey, &sNoEncryptData))
    {
        return WXBizMsgCrypt_DecryptAES_Error;
    }

    sMsg = sNoEncryptData;

    return WXBizMsgCrypt_OK;
}

int WXBizMsgCrypt::EncryptMsg(const std::string &sNeedEncrypt,
                std::string &sEncryptMsg)
{
    if(0 == sNeedEncrypt.size())
    {
        return WXBizMsgCrypt_ParseXml_Error;
    }
    
    //1. AES Encrypt
    std::string sAesData;
    if(0 != AES_CBCEncrypt(sNeedEncrypt, m_sEncodingAESKey, &sAesData))
    {
        return WXBizMsgCrypt_EncryptAES_Error;
    }    
    //2. base64Encode
    if( 0!= EncodeBase64(sAesData,sEncryptMsg) )
    {
        return WXBizMsgCrypt_EncodeBase64_Error;
    }

    return WXBizMsgCrypt_OK;
}

int WXBizMsgCrypt::AES_CBCEncrypt( const std::string & objSource,
        const std::string & objKey, std::string * poResult )
{
    return AES_CBCEncrypt( objSource.data(), objSource.size(),
            objKey.data(), objKey.size(), poResult );
}

int WXBizMsgCrypt::AES_CBCEncrypt( const char * sSource, const uint32_t iSize,
        const char * sKey,  uint32_t iKeySize, std::string * poResult )
{
    if ( !sSource || !sKey || !poResult || iSize <= 0)
    {
        return -1;
    }
    
    poResult->clear();

    int padding = kAesKeySize - iSize % kAesKeySize;

    char * tmp = (char*)malloc( iSize + padding );
    if(NULL == tmp)
    {
        return -1;
    }
    memcpy( tmp, sSource, iSize );
    memset( tmp + iSize, padding, padding );
    
    unsigned char * out = (unsigned char*)malloc( iSize + padding );
    if(NULL == out)
    {
        FREE_PTR(tmp);
        return -1;
    }

    unsigned char key[ kAesKeySize ] = { 0 };
    unsigned char iv[ kAesIVSize ] = { 0 };
    memcpy( key, sKey, iKeySize > kAesKeySize ? kAesKeySize : iKeySize );
    memcpy(iv, key, sizeof(iv) < sizeof(key) ? sizeof(iv) : sizeof(key));

    AES_KEY aesKey;
    AES_set_encrypt_key( key, 8 * kAesKeySize, &aesKey );
    AES_cbc_encrypt((unsigned char *)tmp, out,iSize + padding,  &aesKey, iv, AES_ENCRYPT);
    poResult->append((char*)out, iSize + padding);
    
    FREE_PTR(tmp);
    FREE_PTR(out);
    return 0;
}

int WXBizMsgCrypt::AES_CBCDecrypt( const std::string & objSource,
        const std::string & objKey, std::string * poResult )
{
    return AES_CBCDecrypt( objSource.data(), objSource.size(),
            objKey.data(), objKey.size(), poResult );
}

int WXBizMsgCrypt::AES_CBCDecrypt( const char * sSource, const uint32_t iSize,
        const char * sKey, uint32_t iKeySize, std::string * poResult )
{
    if ( !sSource || !sKey || iSize < kAesKeySize || iSize % kAesKeySize != 0 || !poResult)
    {
        return -1;
    }
    
    poResult->clear();

    unsigned char * out = (unsigned char*)malloc( iSize );
    if(NULL == out)
    {
        return -1;
    }

    unsigned char key[ kAesKeySize ] = { 0 };
    unsigned char iv[ kAesIVSize ] = {0} ;
    memcpy( key, sKey, iKeySize > kAesKeySize ? kAesKeySize : iKeySize );
    memcpy(iv, key, sizeof(iv) < sizeof(key) ? sizeof(iv) : sizeof(key));

    int iReturnValue = 0;
    AES_KEY aesKey;
    AES_set_decrypt_key( key, 8 * kAesKeySize, &aesKey );
    AES_cbc_encrypt( (unsigned char *)sSource, out, iSize, &aesKey, iv ,AES_DECRYPT);
    if( out[iSize-1] > 0 && out[iSize-1] <= kAesKeySize && (iSize - out[iSize-1]) > 0 )
    {
        poResult->append( (char *)out , iSize - out[iSize-1] );
    } else {
        iReturnValue = -1;
    }

    FREE_PTR(out);
    return iReturnValue;
}

int WXBizMsgCrypt::EncodeBase64(const std::string sSrc, std::string & sTarget)
{
    if(0 == sSrc.size() || kMaxBase64Size < sSrc.size())
    {
        return -1;
    }
    
    uint32_t iBlockNum = sSrc.size() / 3;
    if (iBlockNum * 3 != sSrc.size())
    {
        iBlockNum++;
    }
    uint32_t iOutBufSize = iBlockNum * 4 + 1;
    
    char * pcOutBuf = (char*)malloc( iOutBufSize);
    if(NULL == pcOutBuf)
    {
        return -1;
    }
    int iReturn = 0;
    int ret = EVP_EncodeBlock((unsigned char*)pcOutBuf, (const unsigned char*)sSrc.c_str(), sSrc.size());
    if (ret > 0 && ret < (int)iOutBufSize)
    {
        sTarget.assign(pcOutBuf,ret);
    }
    else
    {
        iReturn = -1;
    }
    
    FREE_PTR(pcOutBuf);
    return iReturn;
}


int WXBizMsgCrypt::DecodeBase64(const std::string sSrc, std::string & sTarget)
{
    if(0 == sSrc.size() || kMaxBase64Size < sSrc.size())
    {
        return -1;
    }
    
    //¼ÆËãÄ©Î²=ºÅ¸öÊý
    int iEqualNum = 0;
    for(int n= sSrc.size() - 1; n>=0; --n)
    {
        if(sSrc.c_str()[n] == '=')
        {
            iEqualNum++;
        }
        else
        {
            break;
        }
    }
    
    int iOutBufSize = sSrc.size();
    char * pcOutBuf = (char*)malloc( iOutBufSize);
    if(NULL == pcOutBuf)
    {
        return -1;
    }
    
    int iRet = 0;
    int iTargetSize = 0;
    iTargetSize =  EVP_DecodeBlock((unsigned char*)pcOutBuf, (const unsigned char*)sSrc.c_str(), sSrc.size());
    if(iTargetSize > iEqualNum && iTargetSize < iOutBufSize)
    {
        sTarget.assign(pcOutBuf, iTargetSize - iEqualNum);
    }
    else
    {
        iRet = -1;
    }
    
    FREE_PTR(pcOutBuf);
    return iRet;
}

}

