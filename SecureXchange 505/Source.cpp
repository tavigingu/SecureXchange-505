#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#include "KeyGenerator.h"		

int main()
{

	KeyGenerator::getInstance().generateECKeyPair("public.pem", "private.pem", "parola_secreta");
	
	



	return 0;
}