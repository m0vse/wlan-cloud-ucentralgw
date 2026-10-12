// Isolated real TLS/WebSocket transport regression; synthetic clients only.
#include <Poco/Environment.h>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/SecureServerSocket.h>
#include <Poco/Net/WebSocket.h>
#include <Poco/Net/SSLManager.h>
#include <Poco/Net/Context.h>
#include <Poco/Net/NetSSL.h>
#include <Poco/Buffer.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
std::atomic<unsigned> errors{0},messages{0};
class Handler:public Poco::Net::HTTPRequestHandler {
 void handleRequest(Poco::Net::HTTPServerRequest& q,Poco::Net::HTTPServerResponse& r) override {
  try {
   Poco::Net::WebSocket ws(q,r);ws.setBlocking(false);ws.setMaxPayloadSize(512000);
   // Reactor readiness can be consumed before this handler reads. An empty
   // non-blocking read must remain retryable and keep the same TLS session.
   Poco::Buffer<char> empty(0);int emptyFlags=0;
   int emptySize=ws.receiveFrame(empty,emptyFlags);
   if(emptySize>=0||emptyFlags!=0)throw std::runtime_error("empty non-blocking read was not retryable");
   auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
   while(std::chrono::steady_clock::now()<deadline) {
    if(!ws.poll(Poco::Timespan(0,10000),Poco::Net::Socket::SELECT_READ))continue;
    Poco::Buffer<char> b(0);int flags=0;int n=ws.receiveFrame(b,flags);
    if(n<0&&flags==0)continue;
    if(n==0&&flags==0)return;
    auto op=flags&Poco::Net::WebSocket::FRAME_OP_BITMASK;
    if(op==Poco::Net::WebSocket::FRAME_OP_CLOSE)return;
    if(op==Poco::Net::WebSocket::FRAME_OP_PING){ws.sendFrame("",0,0x8a);continue;}
    if(op!=Poco::Net::WebSocket::FRAME_OP_TEXT||n!=512||std::string(b.begin(),n)!=std::string(512,'x'))throw std::runtime_error("frame corrupted");
    messages++;ws.sendFrame("OK",2,Poco::Net::WebSocket::FRAME_TEXT);
   }
   throw std::runtime_error("transport deadline");
  } catch(const Poco::Exception& e){errors++;std::cerr<<e.displayText()<<'\n';}
    catch(const std::exception& e){errors++;std::cerr<<e.what()<<'\n';}
 }
};
class Factory:public Poco::Net::HTTPRequestHandlerFactory {
 Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest&)override{return new Handler;}
};
int main(int argc,char** argv){
 if(argc!=3)return 2;Poco::Net::initializeSSL();
 Poco::Net::Context::Ptr ctx=new Poco::Net::Context(Poco::Net::Context::SERVER_USE,argv[1],argv[2],"",Poco::Net::Context::VERIFY_NONE);
 Poco::Net::SSLManager::instance().initializeServer(nullptr,nullptr,ctx);
 Poco::Net::SecureServerSocket s(Poco::Net::SocketAddress("127.0.0.1",0),64,ctx);
 Poco::Net::HTTPServer server(new Factory,s,new Poco::Net::HTTPServerParams);server.start();
 std::cout<<"PORT "<<s.address().port()<<" VERSION "<<std::hex<<Poco::Environment::libraryVersion()<<std::dec<<std::endl;
 std::string done;std::getline(std::cin,done);server.stopAll(true);
 std::cout<<"MESSAGES "<<messages<<" ERRORS "<<errors<<std::endl;
 return errors?1:0;
}
