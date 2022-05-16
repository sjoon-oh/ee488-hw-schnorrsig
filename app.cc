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
#undef __PRINT

#include <iostream>
#include <functional>
#include <vector>

#include "schnorr.h"
using namespace EE488;

/* Communicator Class
 * : This class represents communicators, 
 */
class Communicator {
private:
    std::string name;               // Who am I?
    SchnorrSignature sig_manager;   // Signature Manager

public:
    Communicator(const char* arg_name) : name(arg_name) {}
    ~Communicator() = default;

    /* Getter */ 
    SchnorrSignature* get_manager() { return &sig_manager; };

    /* Run do_ series, Wrapper */
    int prepare_key_r(const int arg_bits) { return sig_manager.do_keygen_r(arg_bits); }
    int prepare_msg(const char* arg_msg) { return sig_manager.do_regmsg(arg_msg); }

    int reset_all() { return sig_manager.do_reset(); }

    /* Rx, Tx */
};

/*
 * Test functions
 */
typedef std::function<void()> __test_func__;
std::vector<__test_func__> testf;

void test_scenario_2_success();
void test_scenario_2_fail();

void test_scenario_multi();




int main() {

    std::cout << "[EE488] HW5, Author: SukJoon Oh\n";

    testf = std::vector<__test_func__>{
        /*
         * Add here for more tests.
         */
        test_scenario_2_success,
        test_scenario_2_fail,
        test_scenario_multi
    };
    
    /*
     * The communicators should follow the sequence for Digital 
     * Signaturing
     *  a) Create instance for each communicators. Each communicator has its own 
     *      SchnorrSignature instance as a member to utilize.
     *  b) Call SchnorrSignature::do_keygen_r. The function generates necessary 
     *      parameters, specifically prime numbers p, q and g. do_keygen_r depends 
     *      on OpenSSL lib, DSA for generating such values. All the results are 
     *      stored in the DSA container, but only three values are only needed, 
     *      nothing else. do_keygen_r extracts such parameters and manages the values, 
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



void test_scenario_2_success() {
    std::cout << "Test <test_scenario_2_success>\n";

    /* Step a) */
    Communicator alice("Alice");
    Communicator bob("Bob");

    /* Step b) */
    alice.prepare_key_r(1024);
    bob.prepare_key_r(1024);

}

void test_scenario_2_fail() {
    std::cout << "Test <test_scenario_2_fail>\n";

}

void test_scenario_multi() {
    std::cout << "Test <test_scenario_multi>\n";

}