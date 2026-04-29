//%LICENSE////////////////////////////////////////////////////////////////
//
// Licensed to The Open Group (TOG) under one or more contributor license
// agreements.  Refer to the OpenPegasusNOTICE.txt file distributed with
// this work for additional information regarding copyright ownership.
// Each contributor licenses this file to you under the OpenPegasus Open
// Source License; you may not use this file except in compliance with the
// License.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
//////////////////////////////////////////////////////////////////////////
//
//%/////////////////////////////////////////////////////////////////////////////

#ifndef Pegasus_SSLContextRep_h
#define Pegasus_SSLContextRep_h

#ifdef PEGASUS_HAS_SSL
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/rand.h>

//Include the applink.c to stop crashes as per OpenSSL FAQ
//http://www.openssl.org/support/faq.html#PROG
# ifdef PEGASUS_OS_TYPE_WINDOWS
 # include<openssl/applink.c>
# endif

#else
# define SSL_CTX void
#endif

#include <Pegasus/Common/SSLContext.h>
#include <Pegasus/Common/Mutex.h>
#include <Pegasus/Common/Threads.h>
#include <Pegasus/Common/Tracer.h>
#include <Pegasus/Common/AutoPtr.h>
#include <Pegasus/Common/SharedPtr.h>

PEGASUS_NAMESPACE_BEGIN

#ifdef PEGASUS_HAS_SSL
struct FreeX509STOREPtr
{
    void operator()(X509_STORE* ptr)
    {
        X509_STORE_free(ptr);
    }
};
#else
struct FreeX509STOREPtr
{
    void operator()(X509_STORE*)
    {
    }
};
#endif


#ifdef PEGASUS_HAS_SSL

class SSLEnvironmentInitializer
{
public:

    SSLEnvironmentInitializer()
    {
        AutoMutex autoMut(_instanceCountMutex);

        PEG_TRACE((TRC_SSL, Tracer::LEVEL4,
            "In SSLEnvironmentInitializer(), _instanceCount is %d",
            _instanceCount));

        if (_instanceCount == 0)
        {
            // OpenSSL 3.0+ initializes automatically on first use.
            // An explicit call ensures it is initialised here, prior
            // to any concurrent usage, and loads error strings.
            OPENSSL_init_ssl(
                OPENSSL_INIT_LOAD_SSL_STRINGS |
                OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
        }

        _instanceCount++;
    }

    ~SSLEnvironmentInitializer()
    {
        AutoMutex autoMut(_instanceCountMutex);
        _instanceCount--;

        PEG_TRACE((TRC_SSL, Tracer::LEVEL4,
            "In ~SSLEnvironmentInitializer(), _instanceCount is %d",
            _instanceCount));

        // OpenSSL 3.0+ cleans up automatically at process exit.
    }

private:

    SSLEnvironmentInitializer(const SSLEnvironmentInitializer&);
    SSLEnvironmentInitializer& operator=(const SSLEnvironmentInitializer&);

    /**
        Count of the instances of this class.  The SSL environment must be
        initialized when the first SSLEnvironmentInitializer is constructed.
    */
    static int _instanceCount;

    /**
        Mutex for controlling access to _instanceCount.
    */
    static Mutex _instanceCountMutex;
};

#endif

class SSLCallbackInfoRep
{
public:
    SSLCertificateVerifyFunction* verifyCertificateCallback;
    Array<SSLCertificateInfo*> peerCertificate;
    X509_STORE* crlStore;

    String ipAddress;

    friend class SSLCallback;

    friend class SSLCallbackInfo;
};

class PEGASUS_COMMON_LINKAGE SSLContextRep
{
public:

    /** Constructor for a SSLContextRep object.
    @param trustStore  trust store file path
    @param certPath  server certificate file path
    @param keyPath  server key file path
    @param verifyCert  function pointer to a certificate verification
    call back function.
    @param randomFile  file path of a random file that is used as a seed
    for random number generation by OpenSSL.

    @exception SSLException  exception indicating failure to create a context.
    */
    SSLContextRep(
        const String& trustStore,
        const String& certPath = String::EMPTY,
        const String& keyPath = String::EMPTY,
        const String& crlPath = String::EMPTY,
        SSLCertificateVerifyFunction* verifyCert = NULL,
        const String& randomFile = String::EMPTY,
        const String& cipherSuite = String::EMPTY,
        const Boolean& sslBackwardCompatibility = false);

    SSLContextRep(const SSLContextRep& sslContextRep);

    ~SSLContextRep();

    SSL_CTX * getContext() const;

    String getTrustStore() const;

    String getCertPath() const;

    String getKeyPath() const;

    String getCipherSuite() const;

#ifdef PEGASUS_USE_DEPRECATED_INTERFACES
    String getTrustStoreUserName() const;
#endif

    String getCRLPath() const;

    SharedPtr<X509_STORE, FreeX509STOREPtr> getCRLStore() const;

    void setCRLStore(X509_STORE* store);

    Boolean isPeerVerificationEnabled() const;

    SSLCertificateVerifyFunction* getSSLCertificateVerifyFunction() const;

    /**
        Checks if the certificate associated with this SSL context has expired
        or is not yet valid.
        @exception SSLException if the certificate is determined to be invalid.
    */
    void validateCertificate();

private:

#ifdef PEGASUS_HAS_SSL
    /**
        Ensures that the SSL environment remains initialized for the lifetime
        of the SSLContextRep object.
    */
    SSLEnvironmentInitializer _env;
#endif

    SSL_CTX * _makeSSLContext();
    void _randomInit(const String& randomFile);
    Boolean _verifyPrivateKey(SSL_CTX *ctx, const String& keyPath);

    String _trustStore;
    String _certPath;
    String _keyPath;
    String _crlPath;
    String _randomFile;
    String _cipherSuite;
    Boolean _sslBackwardCompatibility;
    SSL_CTX * _sslContext;

    Boolean _verifyPeer;

    SSLCertificateVerifyFunction* _certificateVerifyFunction;

    SharedPtr<X509_STORE, FreeX509STOREPtr> _crlStore;
};

PEGASUS_NAMESPACE_END

#endif /* Pegasus_SSLContextRep_h */
