/* Author: SukJoon Oh
 * Test Environment: 
 *  - Manjaro Quonos 21.2, Native Desktop
 *      g++ (GCC) 11.2.0,
 *      OpenSSL 1.1.1n 
 *      (comes default in coreutils, no additional installation needed)
 *  - Ubuntu 20.04.4 LTS (Focal Fossa), VM Instance
 *      g++ (GCC) 9.4.0
 *      OpenSSL 1.1.1f
 *      libssl-dev needed, not default in RAW Ubuntu 20.04.
 *          run: apt install libssl-dev
 * Compilation Option: -lssl -lcrypto
 *      Please compile with -std=c++17.
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
   
    signature_manager.do_keygen(1024, 0); // Calling Real-keygen

    std::cout << "---- Key generation test done.\n";
    std::cout << "---- Registering message test.\n";
    
    /* Given Test Vector */
    signature_manager.do_regmsg("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");   

    std::cout << "---- Registering message test done.\n";
    std::cout << "---- Hashing test.\n";

    signature_manager.do_hash(0);

    /* Expected: 
     * 248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1 */
    
    std::cout << "---- Hashing test done.\n";
    std::cout << "---- Signing test.\n";

    signature_manager.do_sign(0);

    std::cout << "---- Signing test done.\n";
    std::cout << "---- Reset-run-again test.\n";
    
    signature_manager.do_reset();
    signature_manager.do_sign(0);
    
    std::cout << "---- Reset-run-again test done.\n";
    std::cout << "---- Re-generate/register/sign.\n";

    // Generate again.
    signature_manager.do_keygen(1024, 0);
    signature_manager.do_regmsg("This is 2nd registered string.");
    
    signature_manager.do_sign(0);

    std::cout << "---- Re-generate/register/sign done.\n";
    std::cout << "---- Verification test.\n";

    bool ret_code = signature_manager.do_verify(0);
    
    if (ret_code)
        std::cout << "---- \tNot verified.\n";
    else
        std::cout << "---- \tVerified.\n";

    std::cout << "---- Verification test done.\n";
    std::cout << "---- Toy test.\n";

    const int bit_l = 20;
    const int bit_n = 10;

    signature_manager.do_reset();
    signature_manager.set_toy(true);

    signature_manager.do_keygen(bit_l, bit_n);
    signature_manager.do_regmsg("This is toyed registered string.");

    signature_manager.do_sign(bit_n);

    signature_manager.do_regmsg("This is toyed registered string.");
    ret_code = signature_manager.do_verify(bit_n);

    if (ret_code)
        std::cout << "---- \tNot verified.\n";
    else
        std::cout << "---- \tVerified.\n";

    std::cout << "---- Toy test done.\n";

    return 0;

}

