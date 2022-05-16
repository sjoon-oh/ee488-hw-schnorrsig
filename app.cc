/* Author: SukJoon Oh
 * Environment: 
 *      Manjaro Quonos 21.2, 
 *      g++ (GCC) 11.2.0,
 *      OpenSSL 1.1.1n (comes default in coreutils)
 * Compilation Option: -lssl -lcrypto
 *      Refer to Makefile for more information.
 * Legal Stuff: None
 */

#define __PRINT

#include <iostream>

#include "schnorr.h"

int main() {

    std::cout << "#############################################\n";
    std::cout << "[EE488] HW5, Author: SukJoon Oh\n";
    std::cout << "Start >\n";

    using namespace EE488;


    SchnorrSignature signature_manager; 

    signature_manager.do_keygen();
    signature_manager.do_regmsg("This is registered string.");


    signature_manager.do_sign();






    std::cout << "Done >\n";
    return 0;
}