/* Author: SukJoon Oh
 * Environment: 
 *      Manjaro Quonos 21.2, 
 *      g++ (GCC) 11.2.0,
 *      OpenSSL 1.1.1n (comes default in coreutils)
 * Compilation Option: -lssl -lcrypto
 *      Refer to Makefile for more information.
 * Legal Stuff: None
 */

/* Every API information can be found in the official document:
 *  https://www.openssl.org, specifically https://www.openssl.org/docs/man1.1.1/man3/
 */

#define __PRINT

#include <iostream>

#include "schnorr.h"

int main () {

    
    std::cout << "[EE488] HW5, Author: SukJoon Oh\n";
    std::cout << "---- This is API test.\n";

    std::cout << "Start >\n";

    EE488::SchnorrSignature signature_manager;  // Hello manager!
    
    std::cout << "---- Key generation test.\n";
    
    signature_manager.do_keygen_r(1024);

    signature_manager.do_keygen_t(20, 20);

    std::cout << "---- Key generation test done.\n";
    std::cout << "---- Registering message test.\n";

    signature_manager.do_regmsg("This is registered string.");
    
    std::cout << "---- Registering message test done.\n";
    std::cout << "---- Signing test.\n";
    

    signature_manager.do_sign();

    std::cout << "---- Signing test done.\n";
    std::cout << "---- Reset-run-again test.\n";
    
    signature_manager.do_reset();
    signature_manager.do_sign();
    
    std::cout << "---- Reset-run-again test done.\n";
    std::cout << "---- Re-generate/register/sign.\n";

    // Generate again.
    signature_manager.do_keygen_r(1024);
    signature_manager.do_regmsg("This is 2nd registered string.");
    signature_manager.do_sign();

    std::cout << "---- Re-generate/register/sign done.\n";
    std::cout << "---- Verification test.\n";

    bool ret_code = signature_manager.do_verify();
    
    if (ret_code)
        std::cout << "---- Test fail.\n";
    else
        std::cout << "---- Test done.\n";

    std::cout << "---- Finished.\n";

    return 0;

}

