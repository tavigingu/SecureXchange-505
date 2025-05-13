#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)
#include "Communication.h"

int main()
{

	Entity entityA(IDGenerator::generate(), "Bob");
	Entity entityB(IDGenerator::generate(), "Alice");

    Communication my_secure_communication(entityA, entityB);
    my_secure_communication.__trust_me_bro_transaction__("Transfer 69420 BTC to 0xDEADBEEF", "Business Expense Report");
	//																message							subject




	return 0;
}