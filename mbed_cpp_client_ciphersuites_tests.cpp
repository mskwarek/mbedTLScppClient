#include <gtest/gtest.h>

#include "common/SslClient.h"
#include "test_cases.cpp"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <exception>
#include <map>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/fusion/container/map.hpp>
#include <boost/fusion/include/map.hpp>
#include <boost/fusion/container/map/map_fwd.hpp>
#include <boost/fusion/include/map_fwd.hpp>
#include <boost/foreach.hpp>


class MbedClient
{
  SslClient cl; 
  unsigned char psk[MBEDTLS_PSK_MAX_LEN];
  size_t psk_len = 0;
  const char *alpn_list[10];
protected:
    Options* opt;
public:
  MbedClient()
  {  
    opt = new Options();

#if defined(MBEDTLS_SSL_ALPN)
    memset( (void * ) this->alpn_list, 0, sizeof( this->alpn_list ) );
#endif 
  }

  virtual void SetUp(std::string ciphersuite)
  {}

  void SetUpCommon()
  {
    opt->auth_mode=MBEDTLS_SSL_VERIFY_REQUIRED;
    opt->force_ciphersuite[1] = 0;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( (this->opt)->debug_level );
#endif
    if((this->opt)->IsCiphersuiteForced())
      (this->opt)->HandleCiphersuiteRequest();

    if((this->opt)->IsPSKEnabled())
      (this->opt)->UnhexifyPSK(this->psk, this->psk_len);

#if defined(MBEDTLS_SSL_ALPN)
    (this->opt)->SslAlpn(this->alpn_list);
#endif /* MBEDTLS_SSL_ALPN */
  }

  void Perform()
  {
    try{
      this->SetUpCommon(); 
      (this->cl).InitRng();
      (this->cl).LoadTrustedCerts(*(this->opt));
      (this->cl).LoadClientKeys(*(this->opt));
      (this->cl).StartConnection(*(this->opt));
      (this->cl).SetupStuff(*(this->opt), this->alpn_list, this->psk, this->psk_len);
      (this->cl).PerformHandshake(*(this->opt));
      (this->cl).VerifyServerCert(*(this->opt));
      (this->cl).SendGet(*(this->opt));
      (this->cl).ReadResponse(*(this->opt));
      (this->cl).ReuseConnection(*(this->opt));
      (this->cl).CloseConnection();
      (this->cl).Reconnect(*(this->opt));
    }

    catch(MbedException e){
      e.what();
      throw e;
    }
  }

  virtual ~MbedClient()
  {
    delete opt;
  }
};

class MbedClientEc : public MbedClient
{
public:
  virtual void SetUp(std::string ciphersuite)
  {
    opt->force_ciphersuite[0] = mbedtls_ssl_get_ciphersuite_id(ciphersuite.c_str());
    if(opt->force_ciphersuite[0] == 0 )
      throw 1;
    opt->server_port = "443";
    opt->ca_file="/home/marcin/mkoi_certs/ec_certs/localh.crt";
    opt->crt_file = "/home/marcin/mkoi_certs/ec_certs/localh_c.crt";
    opt->key_file = "/home/marcin/mkoi_certs/ec_certs/localh_c.pem";
  }
};

class MbedClientRsa : public MbedClient
{
public:
  virtual void SetUp(std::string ciphersuite){
    opt->force_ciphersuite[0] = mbedtls_ssl_get_ciphersuite_id(ciphersuite.c_str());
    if(opt->force_ciphersuite[0] == 0 )
      throw 1;
    opt->server_port = "4443";
    opt->ca_file="/home/marcin/mkoi_certs/certs/localhost.crt";
    opt->crt_file = "/home/marcin/mkoi_certs/certs/localhost_c.crt";
    opt->key_file = "/home/marcin/mkoi_certs/certs/localhost_c.pem";
  }
};

class MbedClientDh : public MbedClient
{
public:
  virtual void SetUp(std::string ciphersuite)
  {
    opt->force_ciphersuite[0] = mbedtls_ssl_get_ciphersuite_id(ciphersuite.c_str());
    if(opt->force_ciphersuite[0] == 0 )
      throw 1;
    opt->server_port = "1443";
    opt->ca_file="/home/marcin/mkoi_certs/certs/localho.crt";
    opt->crt_file = "/home/marcin/mkoi_certs/dsacerts/localho_c.crt";
    opt->key_file = "/home/marcin/mkoi_certs/dsacerts/localho_c.pem";
  }
};

class CppClientTest
{
public:
  MbedClient *cl;
  CppClientTest()
  {
  }
  ~CppClientTest()
  {
    delete cl;
  }
};

class CppClientTestRsa : public CppClientTest, public ::testing::TestWithParam<std::string>
{};
TEST_P(CppClientTestRsa, HandshakeTest)
{
 try{
   cl = new MbedClientRsa();
   cl->SetUp(GetParam());
   cl->Perform();
  }
  catch(...){
    EXPECT_EQ(1,2);
  } 
};

class CppClientTestEc : public CppClientTest, public ::testing::TestWithParam<std::string>{};
TEST_P(CppClientTestEc, HandshakeTest)
{
  try{
    cl = new MbedClientEc();
    cl->SetUp(GetParam());
    cl->Perform();
  }
  catch(...){
    EXPECT_EQ(1,2);
  }
};

class CppClientTestDsa : public CppClientTest, public ::testing::TestWithParam<std::string>{};
TEST_P(CppClientTestDsa, HandshakeTest)
{
  try{
    cl = new MbedClientDh();
    cl->SetUp(GetParam());
    cl->Perform();
  }
  catch(...){
    EXPECT_EQ(1, 2);
  }
};

//INSTANTIATE_TEST_CASE_P(RSA, CppClientTestRsa, ::testing::ValuesIn(RsaTestCases));
INSTANTIATE_TEST_CASE_P(DheRsaTest, CppClientTestRsa, ::testing::ValuesIn(DheRsaTestCases));
INSTANTIATE_TEST_CASE_P(EcdheRsaTest, CppClientTestRsa, ::testing::ValuesIn(EcdheRsaTestCases));
INSTANTIATE_TEST_CASE_P(EcdheEcdsaTest, CppClientTestEc, ::testing::ValuesIn(EcdheEcdsaTestCases));



int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
