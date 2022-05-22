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

#ifdef __PRINT
#undef __PRINT
#endif

#include <iostream>

#include <functional>
#include <vector>

#include <cassert>

#include "schnorr.h"
using namespace EE488;

#define __msg_out(X)    std::cout << (X)

/* Communicator Class
 * : This class represents communicators, 
 */
class Communicator {
private:
    std::string name;               // Who am I?
    SchnorrSignature sig_manager;   // Signature Manager

    /* Rx */
    int rx_signature();
    int rx_pgq();

public:
    Communicator(const char* arg_name) : name(arg_name) {}
    ~Communicator() = default;

    /* Getter */ 
    SchnorrSignature& get_manager() { return sig_manager; };

    /* Run do_ series, Wrapper */
    // int prepare_key_r(const int arg_bits) { return sig_manager.do_rkeygen(arg_bits); }
    int prepare_key(const int arg_lbits, const int arg_nbits) { return sig_manager.do_keygen(arg_lbits, arg_nbits); }
    int prepare_msg(const char* arg_msg) { return sig_manager.do_regmsg(arg_msg); }

    int generate_sig(const int arg_nbits) { return sig_manager.do_sign(arg_nbits); }
    int run_verify(const int arg_nbits) { return sig_manager.do_verify(arg_nbits); }

    int reset_all() { return sig_manager.do_reset(); }

    /* Setter */
    int set_toy(bool arg_toy) { return sig_manager.set_toy(arg_toy); }

    /* Tx */
    void tx_signature(Communicator& arg_to) {
        arg_to.get_manager().set_signature_pair(
            const_cast<BIGNUM*>(sig_manager.get_signature_s()),
            const_cast<BIGNUM*>(sig_manager.get_signature_e())
        );
    };

    void tx_pqg(Communicator& arg_to) {
        arg_to.get_manager().set_pqg(
            const_cast<BIGNUM*>(sig_manager.get_p()),
            const_cast<BIGNUM*>(sig_manager.get_q()),
            const_cast<BIGNUM*>(sig_manager.get_g())
        );
    };

    void tx_pk(Communicator& arg_to) {
        arg_to.get_manager().set_pk(
            const_cast<BIGNUM*>(sig_manager.get_pk()));
    }
};

/*
 * Test functions
 */
typedef std::function<void()> __test_func__;
std::vector<__test_func__> testf;

/* List of sample pre-defined test functions */
void __test_send();
void __test_self_sign_and_verify();
void __test_sig_and_verify_1024_fail();
void __test_sig_and_verify_1024_success();
void __test_self_sign_and_verify_small_toy();
void __test_self_sign_and_verify_large_toy();
void __test_sig_and_verify_2048_success();

/* main
 */
int main() {

    __msg_out("[EE488] HW5, Author: SukJoon Oh\n");

    testf = std::vector<__test_func__>{
        /*
         * Add here for more tests.
         */
        __test_send,
        __test_self_sign_and_verify,
        __test_sig_and_verify_1024_fail,
        __test_sig_and_verify_1024_success,
        __test_self_sign_and_verify_small_toy,
        __test_self_sign_and_verify_large_toy,
        __test_sig_and_verify_2048_success

    };
    
    /*
     * The communicators should follow the sequence for Digital 
     * Signaturing
     *  a) Create instance for each communicators. Each communicator has its own 
     *      SchnorrSignature instance as a member to utilize.
     *  b) Call SchnorrSignature::do_rkeygen. The function generates necessary 
     *      parameters, specifically prime numbers p, q and g. do_rkeygen depends 
     *      on OpenSSL lib, DSA for generating such values. All the results are 
     *      stored in the DSA container, but only three values are only needed, 
     *      nothing else. do_rkeygen extracts such parameters and manages the values, 
     *      as a 'manager' does.
     * 
     *  c) Register message to sign by calling SchnorrSignature::do_regmsg. The 
     *      arguments can have several forms, such as conventional C-style null-
     *      terminated string, or STL-container based std::string. Other forms are
     *      not yet accepted, but can be easily supported by overloading.
     * 
     *  d) A communicator who wants to sign the message can do by calling
     *      SchnorrSignature::do_sign. To function, the message must be registered
     *      in advance, or will fail. SchnorrSignature is designed to function
     *      after having all of prerequisites it requires. 
     * 
     *  e) When verifying, a communicator who wants to verify can call 
     *      SchnorrSignature::do_verify. The return value is true(0) or false(1).
     * 
     * Now, there are several scenarios prepared in this sample application (app.c) using
     * SchnorrSignature and Commincator objects. The functions are:
     *  - test_scenario_2_success()
     *  - test_scenario_2_fail()
     *  - test_scenario_multi()
     */

    /* Run tests */
    for (auto& f: testf) f();

    return 0;
}

/* Refer to,
 * https://cacr.uwaterloo.ca/hac/about/chap11.pdf 
 */

/* ret codes */
#define VERIFY_SUCCESS  0
#define VERIFY_FAIL     1

#define RX_SUCCESS      0
#define RX_FAIL         1



/* 
 * __test_send 
 */
void __test_send() {
    std::cout << "Test <" << __FUNCTION__ << ">\n";

    /* This sample test checks whether the public parameters
     * are successfully shared between users.
     * Alice and Bob instance are created, and Alice generates
     * its own parameters to be shared.
     * 
     * Alice sends the parameters and the signature
     * by the interfaces of:
     *  - tx_pqg
     *  - tx_signature
     * In this test, message is assumed to be sent by just
     * calling prepare_msg.
     * 
     * If any error occurs, the console will show "Error".
     */

    const int promised_bit_l = 1024; // Not toyed

    /* Step a) */
    Communicator alice("Alice");
    Communicator bob("Bob");

    /* Step b) */
    alice.prepare_key(promised_bit_l, 0);
    alice.tx_pqg(bob);

    {
        __msg_out("  Checking Bob's pqg\n");

        int rc = BN_cmp(
            alice.get_manager().get_p(),
            bob.get_manager().get_p()
        );

        if (rc) __msg_out("> Not received p correctly, Error.\n");
        else    __msg_out("> Received p, OK.\n");

        rc = BN_cmp(
            alice.get_manager().get_q(),
            bob.get_manager().get_q()
        );

        if (rc) __msg_out("> Not received q correctly, Error.\n");
        else    __msg_out("> Received q, OK.\n");
        
        rc = BN_cmp(
            alice.get_manager().get_g(),
            bob.get_manager().get_g()
        );

        if (rc) __msg_out("> Not received g correctly, Error.\n");
        else    __msg_out("> Received g, OK.\n");
    }

    alice.prepare_msg("This is a test message");

    alice.generate_sig(promised_bit_l);
    alice.tx_signature(bob);

    {
        __msg_out("  Checking Bob's signature\n");
        int rc = BN_cmp(
            alice.get_manager().get_signature_e(),
            bob.get_manager().get_signature_e()
        );

        if (rc) __msg_out("> Not received e correctly, Error.\n");
        else    __msg_out("> Received e, OK.\n");

        rc = BN_cmp(
            alice.get_manager().get_signature_s(),
            bob.get_manager().get_signature_s()
        );

        if (rc) __msg_out("> Not received s correctly, Error.\n");
        else    __msg_out("> Received s, OK.\n");
    }
}


/* 
 * __test_self_sign_and_verify 
 */
void __test_self_sign_and_verify() {
    std::cout << "Test <" << __FUNCTION__ << ">\n";

    /* This sample test checks whether generating signature, and 
     * verification of the signature works without any error.
     * If well implemented, the result of the verification function
     * should return 0.
     * 
     * This is a self sign-verification test, which holds all necessary
     * information (parameters, msg, keys, etc. ) in a single user instance,
     * thus the verification should be a sucess. In other words, Alice 
     * generates the signature, and Alice verifies it.
     */

    const int promised_bit_l = 1024;
    const char* msg_1 = "message 1";

    Communicator alice("Alice");
    alice.prepare_key(promised_bit_l, 0);

    alice.prepare_msg(msg_1);
    alice.generate_sig(promised_bit_l);
    
    alice.prepare_msg(msg_1);

    int rc = alice.run_verify(promised_bit_l);

    if (rc) __msg_out("> Not verified, Failed.\n");
    else    __msg_out("> Verified, OK.\n");
}


/* 
 * __test_sig_and_verify 
 */
void __test_sig_and_verify_1024_fail() {
    std::cout << "Test <" << __FUNCTION__ << ">\n";

    /* This sample test checks whether generating signature, and 
     * verification of the signature works without any error.
     * If well implemented, the result of the verification function
     * should return 0.
     * 
     * This is a fail-scenario. Alice and Bob shares the parameters, 
     * but has different message. To be precise, Alice generates 
     * signature with "message 1", and Bob verifies the signature using
     * different message "message 2". The verificatino should thus fail.
     */

    const int promised_bit_l = 1024;

    const char* msg_1 = "message 1";
    const char* msg_2 = "message 2";


    /* Step a) */
    Communicator alice("Alice");
    Communicator bob("Bob");

    /* Step b) */
    alice.prepare_key(promised_bit_l, 0);
    alice.tx_pqg(bob);  // Share public parameters
    alice.tx_pk(bob);

    alice.prepare_msg(msg_1);
    alice.generate_sig(promised_bit_l);

    alice.tx_signature(bob);
    
    bob.prepare_msg(msg_2);

    int rc = bob.run_verify(promised_bit_l);
    
    if (rc) __msg_out("> Not verified, OK.\n");
    else    __msg_out("> Verified, Failed.\n"); 
}


/* 
 * __test_sig_and_verify_1024_success
 */
void __test_sig_and_verify_1024_success() {
    std::cout << "Test <" << __FUNCTION__ << ">\n";

    /* This sample test checks whether generating signature, and 
     * verification of the signature works without any error.
     * If well implemented, the result of the verification function
     * should return 0.
     * 
     * This is a sucess-scenario. Alice and Bob shares the parameters, 
     * but has the same message. Since they both hold the same string, 
     * the result of the verification function should be 0.
     */

    const int promised_bit_l = 1024;

    const char* msg_1 = "message 3";
    const char* msg_2 = "message 3";

    /* Step a) */
    Communicator alice("Alice");
    Communicator bob("Bob");

    /* Step b) */
    alice.prepare_key(promised_bit_l, 0);
    alice.tx_pqg(bob);  // Share public parameters
    alice.tx_pk(bob);

    alice.prepare_msg(msg_1);
    alice.generate_sig(promised_bit_l);

    alice.tx_signature(bob);
    
    bob.prepare_msg(msg_2);

    int rc = bob.run_verify(promised_bit_l);

    std::cout << "  Bob is verifying signature\n";
    
    if (rc) __msg_out("> Not verified, Failed.\n");
    else    __msg_out("> Verified, OK.\n");
}


/* 
 * __test_self_sign_and_verify_small_toy
 */
void __test_self_sign_and_verify_small_toy() {
    std::cout << "Test <" << __FUNCTION__ << ">\n";

    /* This sample test checks whether generating signature, and 
     * verification of the signature works without any error.
     * If well implemented, the result of the verification function
     * should return 0.
     * 
     * This is a toy self-test scenario. If the inner toy flag is not set,
     * the instance (manager) utilizes OpenSSL DSA container to generate
     * the keys and parameters more efficiently. When toy flag is set,
     * a user can generate arbitrary size of p and q, which is not supported
     * in the OpenSSL DSA interface. (The supported size of p and q using 
     * OpenSSL are fixed, such as 1024, 2048, ... etc.) 
     * 
     * Refer to interface of series t** for 'toyed' interfaces:
     *  - thash
     *  - tkeygen
     * These are only used inside of an instance, and activated only when the
     * toy flag is set. The default setting of the toy flag is 'false', which
     * utilizes r** series interfaces for 'real' use.
     * 
     */

    const int promised_bit_l = 20;
    const int promised_bit_n = 8;

    const char* msg_1 = "message 1";

    
    Communicator alice("Alice");
    alice.set_toy(true);

    alice.prepare_key(promised_bit_l, promised_bit_n);

    alice.prepare_msg(msg_1);
    alice.generate_sig(promised_bit_n);
    
    alice.prepare_msg(msg_1);
    int rc = alice.run_verify(promised_bit_n);


    if (rc) __msg_out("> Not verified, Failed.\n");
    else    __msg_out("> Verified, OK.\n");
}



/* 
 * __test_self_sign_and_verify_large_toy
 */
void __test_self_sign_and_verify_large_toy() {
    std::cout << "Test <" << __FUNCTION__ << ">\n";

    /* This sample test checks whether generating signature, and 
     * verification of the signature works without any error.
     * If well implemented, the result of the verification function
     * should return 0.
     * 
     * This is a toy self-test scenario. If the inner toy flag is not set,
     * the instance (manager) utilizes OpenSSL DSA container to generate
     * the keys and parameters more efficiently. When toy flag is set,
     * a user can generate arbitrary size of p and q, which is not supported
     * in the OpenSSL DSA interface. (The supported size of p and q using 
     * OpenSSL are fixed, such as 1024, 2048, ... etc.) 
     * 
     * Refer to interface of series t** for 'toyed' interfaces:
     *  - thash
     *  - tkeygen
     * These are only used inside of an instance, and activated only when the
     * toy flag is set. The default setting of the toy flag is 'false', which
     * utilizes r** series interfaces for 'real' use.
     * 
     */

    const int promised_bit_l = 64;
    const int promised_bit_n = 20;

    const char* msg_1 = "message 1";

    
    Communicator alice("Alice");
    alice.set_toy(true);

    alice.prepare_key(promised_bit_l, promised_bit_n);

    alice.prepare_msg(msg_1);
    alice.generate_sig(promised_bit_n);
    
    alice.prepare_msg(msg_1);
    int rc = alice.run_verify(promised_bit_n);


    if (rc) __msg_out("> Not verified, Failed.\n");
    else    __msg_out("> Verified, OK.\n");
}


/* 
 * __test_sig_and_verify_2048_success
 */
void __test_sig_and_verify_2048_success() {
    std::cout << "Test <" << __FUNCTION__ << ">\n";

    /* This is another success scenario with bit length (L, N)
     * of (2048, 256) for p and q. This uses 'r**' interfaces (untoyed)
     * which utilizes OpenSSL DSA container. If the argument is set
     * to 2048 of DSA_generate_parameters_ex, it automatically sets
     * the parameter p and q to 2048 bits and 256 bits each.
     * 
     * Remember to not to set it 'toyed', in order to benefit from the
     * OpenSSL DSA instance.
     */

    const int promised_bit_l = 2048;

    const char* msg_1 = "message 3";
    const char* msg_2 = "message 3";

    /* Step a) */
    Communicator alice("Alice");
    Communicator bob("Bob");

    /* Step b) */
    alice.prepare_key(promised_bit_l, 0);
    alice.tx_pqg(bob);  // Share public parameters
    alice.tx_pk(bob);

    alice.prepare_msg(msg_1);
    alice.generate_sig(promised_bit_l);

    alice.tx_signature(bob);
    
    bob.prepare_msg(msg_2);

    int rc = bob.run_verify(promised_bit_l);

    std::cout << "  Bob is verifying signature\n";
    
    if (rc) __msg_out("> Not verified, Failed.\n");
    else    __msg_out("> Verified, OK.\n");
}