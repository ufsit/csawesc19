#include <hashlibpp.h>
#include <string>
#include <iostream>  //for "cerr"
#include <sstream>
#include <memory.h>

std::string convToString(unsigned char *data)
{
	/*
	 * using a ostringstream to convert the hash in a
	 * hex string
	 */
	std::ostringstream os;
	for(int i=0; i<16; ++i)
	{
		/*
		 * set the width to 2
		 */
		os.width(2);

		/*
		 * fill with 0
		 */
		os.fill('0');

		/*
		 * conv to hex
		 */
		os << std::hex << static_cast<unsigned int>(data[i]);
	}

	/*
	 * return as std::string
	 */
	return os.str();
}

int main() 
{
  unsigned char buff[16] = "";	
  std::string target = "703224f765d313ee4ed0fadcf9d63a5e";

  for (int i = 0; i < 255; i++) {
    MD5 * md5 = new MD5();
    HL_MD5_CTX ctx;
    unsigned char inp = i;

    memset(&ctx, 0, sizeof(ctx));

    md5->MD5Init(&ctx);
    md5->MD5Update(&ctx, &inp, (unsigned int)1);
    md5->MD5Final((unsigned char *)buff, &ctx);

    std::string hexdigest = convToString(buff);

    for (int j = 0; j < 9; j++) {
      md5->MD5Update(&ctx, (unsigned char *)hexdigest.c_str(), 32);
      md5->MD5Final((unsigned char *)buff, &ctx);

      hexdigest = convToString(buff);
    }

    if (hexdigest == target) {
      std::cout << "Got it: " << inp << std::endl;
      break;
    }

    delete md5;
  }
}
