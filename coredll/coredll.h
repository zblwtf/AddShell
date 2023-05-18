#pragma once
#include <WinSock2.h>
#pragma comment(lib,"Ws2_32.dll")
class tcp_stream
{
public:
	enum {buffsize = 4096};
	typedef typename unsigned long streampos;
	typedef typename unsigned long streamoff;
	typedef typename unsigned long streamsize;
	enum class seedir
	{
		begin = 1,
		current = 2,
		end = 3
	};
	tcp_stream();
	~tcp_stream();
	unsigned char* buff;
	void read(char* buffer,unsigned int offset, int size);
	void readsome(char* buffer, streamsize);
	void write(const char* buffer,unsigned int offset, int size);
	tcp_stream& tellg();
	tcp_stream& seekg(streampos pos);
	tcp_stream& seekg(streamoff off, seedir way);
};
class transport_manager
{
public:
	
};

