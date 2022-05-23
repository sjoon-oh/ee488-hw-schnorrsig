# [EE488] Assignment 5

## Introduction to Cryptographic Engineering, Spring 2022.
---

This repository is the implementation of Schnorr signature, a part of assignment #5. If you wish to test the executables, **please read the environment requirements** before compilation.

## Setup
---

### Library Installation

This project is tested on the following system

```
- Intel Core i7-10700 @ 2.90GHz
- RAM 31.2 GiB
- Manjaro Linux Quonos 21.2 (Native)
- Ubuntu 20.04.4 LTS (Virtual Machine Instance, Raw)
```

This project heavily depends on **OpenSSL**. Be sure to have your system holds OpenSSL dev-libraries. The compilation/run tests were done on Manjaro, which contains OpenSSL library as its default. However, if you are running some other Arch based distributions, you may not have such libraries. Make sure to have one.

My Ubuntu instance did not have OpenSSL as default, thus manual installation was necessary:

```sh
$ sudo apt install libssl-dev 
# For Debian based, managed by apt-package manager. 
```

Note that running on *yum-managed* Linux distributions were not tested. The compilations were tested using *OpenSSL 1.1.1n* and *OpenSSL 1.1.1f*. Some OpenSSL APIs are deprecated, thus be sure to use 1.1.1 version.

### GCC

Some syntaxes this project has are based on some recent releases of C++. The default *Makefile* contained in this repository sets the version to **C++17**, which is the version I have tested. If you are compiling by setting over **C++11**, it may not have any error, but it is unknown.

The compilers tested are:

```
- g++ (GCC) 11.2.0
- g++ (GCC) 9.4.0
```

To use OpenSSL, you should set the library as GCC argument: `-lssl`, `-lcrypto`.


### Make

The `Makefile` provides some compilation options. 

```sh
$ make # Compiles default. Default process is from the app.cc.
$ make run # Compiles app.cc and runs the program immediately.
$ make test # Compiles api_test.cc.
$ make clean # Deletes all object, executable, log files.
```

Default executable names are set as `schnorr.run` and `api-test.run`. Modify `Makefile` as you wish.


### Structure

This project has several sources, but not many.
- `schnorr.h`, `schnorr.cc` : Implements *Schnorr signature manager*. 
- `api_test.cc` : Utilizes *Schnorr signature manager*, and tests whether the interfaces are working properly. Simple tests.
- `app.cc` : Utilizes *Schnorr signature manager*, and implements some use case scenarios. This implements sample commicator as a class `Communicator`. Read the test codes, for more information.


## API Cheatsheet
---

This section mainly summarizes interface support of the class `SchnorrSignature` defined in `schnorr.h`. As stated, the features heaviliy rely on **OpenSSL** library. For more information, visit the [official document](https://www.openssl.org/docs/man1.1.1/man3/).


### `namespace`, Compatibility
All features are defined in the namespace of `EE488`. 

```cpp
namespace EE488 {
    // ...
```

The OpenSSL compatibility is defined using `#define`, which explicitly notifies the OpenSSL library. Because of this, using other versions of **OpenSSL** may cause error. This project only includes four **OpenSSL** header files.

```cpp
#ifdef __OPENSSL
#define OPENSSL_API_COMPAT  0x10101000L

#include <openssl/dsa.h>
#include <openssl/engine.h>

#include <openssl/bn.h>     // Big number lib
#include <openssl/sha.h>    // SHA256 lib
#endif
```

### Class `BigNumberWrapper` (`bnw_t`)

The `BigNumberWrapper` is a wrapper class of `BIGNUM` pointer type. `BIGNUM` is a structure supported by the OpenSSL, which represents big-sized numbers. This class automatically allocates `BIGNUM` instance to `actor` in multiple constructor/copy consturctor/move constructor, and supports single `operator =`. 

Destructor automatically deallocates the `BIGNUM` as it goes out of scope. This class cannot be inherited, since it is the minimum management unit for `BIGNUM`, without explicitly using *OpenSSL API*.

```cpp
struct BigNumberWrapper final {
    BIGNUM* actor;
    
    BigNumberWrapper();
    BigNumberWrapper(const BigNumberWrapper&);
    BigNumberWrapper(const BigNumberWrapper&&);
    ~BigNumberWrapper();

    BigNumberWrapper& operator =(const BigNumberWrapper&);
};

using bnw_t = BigNumberWrapper;
```

### Class `BigNumberManager`

The `BigNumberManager` manages `bnw_t`, stored in the `std::vector`, `asset`. The size of a vector is fixed and never modified, thus if you wish to substitute the container to `std::array`, feel free to modify. 

The size of the vector is the number of parameters, keys, or any value necessary for calculation. The values are defined in anonymous `enum` in the same namespace `EE488`, and the size is `NPARAMS`, or `11` in constant. `bnw_t` constructors are automatically called in initiation of the `asset`, which implies the instance are allocated automatically.

```cpp
class BigNumberManager {
private:
    std::vector<bnw_t> asset;

public:
    BigNumberManager();
    BigNumberManager(std::vector<bnw_t>*);
    ~BigNumberManager() = default;

    void set_asset(BIGNUM*, int);
    void set_keys(BIGNUM*, BIGNUM*);
    
    const BIGNUM* get_asset(int);
        // Do not try to manually free the member 'actor'.

    void reset_asset();
};

using bnm_t = BigNumberManager;
```

These are the accessible interfaces.

- `set_asset` : Copies the value to the given index.
- `set_keys` : Copies the value to the given index.
- `get_asset` : Provides reads of the array member `asset`. The function can be called as `manager.get_asset(BN_P)`, using pre-defined index declared by `enum`. The return type is fixed to `const`, thus be cautious when modifying access rights using `const_cast`, which cannot be blocked, as it may corrupt the member.
- `reset_asset` : Clears all members using `BN_Clear`. It does not deallocate `BIGNUM`.


### Class `SchnorrSignature`

\* *Only `public` functions are stated in this section.*

The class `SchnorrSignature` contains single `BigNumberManager`. All inner functions requests modification of the values using its `BigNumberManager` typed member, `manager`. Code box below shows all the declaration of the `public` methods.

```cpp
int do_keygen(const int arg_l, const int arg_n);

int do_regmsg(const char*);
int do_regmsg(std::string);

BIGNUM* do_hash(const int arg_n);

int do_sign(const int arg_n);
int do_verify(const int arg_n);

int do_reset();

/* 
 * Getters, inline */
const unsigned char* get_mstr();
const unsigned char* get_sha_digest();

const BIGNUM* get_signature_s();
const BIGNUM* get_signature_e();

const bnm_t* get_manager() const;

const BIGNUM* get_p();
const BIGNUM* get_q();
const BIGNUM* get_g();

const BIGNUM* get_pk();

/* 
 * Setters */
bool set_toy(bool arg_toy);

void set_signature_s(BIGNUM*);
void set_signature_e(BIGNUM*);

inline void set_signature_pair(BIGNUM*, BIGNUM*);

void set_pqg(BIGNUM*, BIGNUM*, BIGNUM*);
void set_pk(BIGNUM*);

/* Validation Checker */
inline const bool is_toy();
inline const bool is_sk_ready();
inline const bool is_pk_ready();
inline const bool is_msg_ready();
inline const bool is_sign_ready();
```

Key digital signature operations are:
- `do_keygen` : Generates key. If the `toy_enable` flag is disabled (as default), the `private` method `do_rkeygen` is called. The flag can be enabled by using `set_toy` as described below. The instance (manager) utilizes **OpenSSL `DSA` container** to generate keys and parameters more efficiently, in `do_rkeygen`. If the flag is enabled, it internally calls `do_tkeygen` which do not use the **OpenSSL `DSA` container**, but randomly generates primes using OpenSSL API `DSA_generate_parameters_ex`. <br> `do_keygen` requires single argument, the bit length of parameter *q*. If *toyed*, then the argument is valid, otherwise it is ignored. 
- `do_regmsg` : Class `SchnorrSignature` have an array of character type (`unsigned char*`), which stores initial and concatenated message (`mstr`). This function copies the string into the member `mstr`. It is overriden, thus normal C-style null-terminated string or `std::string` type can be provided as an argument.
- `do_hash` : Hashes the given string, specically the one stored in the `mstr`. Thus, any valid string should be registered before using this function. The return type is the `BIGNUM*`, which is newly allocated by `BN_new`. If its purpose of existence has ended, be sure to deallocate the number `BN_free`. <br> The single argument is the bit size of the parameter *q*. If the `toy_enable` flag is disabled (as default), the `private` method `do_rhash` is called, which does not modify the result of the hashed value. When *toyed*, the hashed value will only have rightmost bits removed, leaving only leftmost `arg_nbits`, as the assignment guide state (`do_thash`)s. If it is not *toyed*, the argument will be ignored. 
- `do_sign` : This function signs the message, stored in `mstr`. It takes an argument `arg_nbits`. If the toy flag is enabled, it internally calls `do_thash` function, otherwise it will call `do_rhash`.  
- `do_verify` : This function verifies the message. Before running the verification, all necessary parameters in the `manager` should be set. You can manually set the parameters by utilizing setters, described below. Internal validation checker will check whether a message is ready, signature values are ready. But it does not check whether all the parameters are ready. If the toy flag is enabled, it internally calls `do_thash` function (argument will not be ignored), otherwise it will call `do_rhash` (argument will be ignored). 
- `do_reset` : Resets all the fields, including all the parameters it have, which `BigNumManager` `manager` manages.

Use cases can be found in the sample scenaros. Please refer to the [Test Scenarios](#-Test-Scenarios) section.

Other interfaces are just setters and getters, thus will not be explained here in detail. These are the getters for `BIGNUM` typed inner parameters. All utilizes the same interface of `BigNumberManager`'s `get_asset`. Thus, if wished to access manually, you can manually access by `get_manager`. Note that the function prevents any modification of the `manager` itself.

- `get_signature_s`
- `get_signature_e`
- `get_p`
- `get_q`
- `get_g`
- `get_pk`

Setters are listed below. As the getters do, it utilizes interface of `BigNumberManager`'s `set_asset`. The member manager does not expose `set_asset` interface for now.

- `set_toy`
- `set_signature_s`
- `set_signature_e`
- `set_pqg`
- `set_pk`

The functions listed below are flag-checkers. They are used internally, but may be also be used outside of the instance, thus declared as `public`.


## Test Scenarios

The `app.cc` file contains several test scenrios. It defines sample `Communicator` class which each instance represents a communicator. It receives string `name` in its constructor. Each `Comminicator` instance has its own `SchnorrSignature` field `sig_manager` that controls digital signaturing. This file uses comminicator to generate some signaturing tests.

### Class `Communicator`

A `Comminicator` instance is an entity that signs and verifies given messages. It can be viewed as a wrapper of `SchnorrSignature` instance. All method the class defines uses only open interfaces of `SchnorrSignature` described above, mostly getters. Some methods represents send/receive operations of arbitrary two communicators.

Code below shows some of the `private`/`public` methods.

```cpp
class Communicator {
private:

    // ...
    int rx_signature();
    int rx_pgq();

public:

    // ...

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
```

This section will not describe all the function in detail, as they are just wrappers of  `sig_manager`'s setters and getters. The core features of the `Communicator` is:

- `prepare_key`
- `prepare_msg`
- `generate_sig`
- `run_verify`
- `reset_all`
- `set_toy`

### main

Tests are written in this form.
1. All tests return `void` and do not request any parameter, typed as `__test__func__`.
2. These functions are registered when initializing `std::vector`, `testf`.
3. The functions are iterative called, one by one.

```cpp
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

/* Main function starts here.
 */
int main() {

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

    // ...

    /* Run tests */
    for (auto& f: testf) f();
    return 0;
}
```

If you want to add any test function, define yours and add to the vector.


### Scentario 1: `__test_send`

This sample test checks whether the public parameters are successfully shared between users. Alice and Bob instance are created, and Alice generates its own parameters to be shared.

Alice sends the parameters and the signature by the interfaces of:

```
- tx_pqg
- tx_signature
```

In this test, message is assumed to be sent by just calling `prepare_msg`. If any error occurs, the console will show "Error".

```cpp
const int promised_bit_l = 1024; // Not toyed

Communicator alice("Alice");
Communicator bob("Bob");

// Alice prepares her key and parameters
alice.prepare_key(promised_bit_l, 0);

// Alice shares the to Bob
alice.tx_pqg(bob);

// Alice prepares her message, 
alice.prepare_msg("This is a test message");
alice.generate_sig(promised_bit_l); // and generates signature

// Alice sends signature
alice.tx_signature(bob);
```


### Scentario 2: `__test_self_sign_and_verify`

This sample test checks whether generating signature, and verification of the signature works without any error. If well implemented, the result of the verification function should return 0.

This is a self sign-verification test, which holds all necessary information (parameters, msg, keys, etc. ) in a single user instance, thus the verification should be a sucess. In other words, Alice generates the signature, and Alice verifies it.

```cpp
const int promised_bit_l = 1024; // Not toyed
const char* msg_1 = "message 1";

Communicator alice("Alice");

// Alice prepares her key and parameters
alice.prepare_key(promised_bit_l, 0);

// Alice prepares her message, 
alice.prepare_msg(msg_1);
alice.generate_sig(promised_bit_l); // and generates signature

// Alice verifies her signature
alice.run_verify(promised_bit_l);
```

### Scentario 3: `__test_sig_and_verify_1024_fail`


This sample test checks whether generating signature, and verification of the signature  works without any error. If well implemented, the result of the verification function should return 0.

This is a fail-scenario. Alice and Bob shares the parameters, but has different message. To be precise, Alice generates signature with "message 1", and Bob verifies the signature using different message "message 2". The verificatino should thus fail.

```cpp
const int promised_bit_l = 1024; // Not toyed

const char* msg_1 = "message 1";
const char* msg_2 = "message 2";

Communicator alice("Alice");
Communicator bob("Bob");

// Alice prepares her key and parameters
alice.prepare_key(promised_bit_l, 0);

// Alice shares public parameters
alice.tx_pqg(bob);  
alice.tx_pk(bob);

// Alice sets her plaintext
alice.prepare_msg(msg_1);
alice.generate_sig(promised_bit_l); // and generates signature

// Alice shares her signature
alice.tx_signature(bob);

// Bob receives different message
bob.prepare_msg(msg_2);

// Bob verifies received signature
int rc = bob.run_verify(promised_bit_l);
```

### Scentario 4: `__test_sig_and_verify_1024_success`

This sample test checks whether generating signature, and verification of the signature works without any error. If well implemented, the result of the verification function should return 0. 

This is a sucess-scenario. Alice and Bob shares the parameters, but has the same message. Since they both hold the same string, the result of the verification function should be 0.

```cpp
const int promised_bit_l = 1024; // Not toyed

const char* msg_1 = "message 3";
const char* msg_2 = "message 3";

Communicator alice("Alice");
Communicator bob("Bob");

// Alice prepares her key and parameters
alice.prepare_key(promised_bit_l, 0);

// Alice shares public parameters
alice.tx_pqg(bob);  
alice.tx_pk(bob);

// Alice sets her plaintext
alice.prepare_msg(msg_1);
alice.generate_sig(promised_bit_l); // and generates signature

// Alice shares her signature
alice.tx_signature(bob);

// Bob receives same message
bob.prepare_msg(msg_2);

// Bob verifies received signature
int rc = bob.run_verify(promised_bit_l);
```

### Scentario 5: `__test_self_sign_and_verify_small_toy`

This sample test checks whether generating signature, and verification of the signature works without any error. If well implemented, the result of the verification function should return 0.

This is a toy self-test scenario. If the inner toy flag is not set, the instance (manager) utilizes OpenSSL DSA container to generate the keys and parameters more efficiently. When toy flag is set, a user can generate arbitrary size of p and q, which is not supported in the OpenSSL DSA interface. (The supported size of p and q using OpenSSL are fixed, such as 1024, 2048, ... etc.) 

Refer to interface of series `t**` for 'toyed' interfaces:
```
- thash
- tkeygen
```

These are only used inside of an instance, and activated only when the toy flag is set. The default setting of the toy flag is `false`, which utilizes `r**` series interfaces for 'real' use. 

```cpp
const int promised_bit_l = 20;
const int promised_bit_n = 8;

const char* msg_1 = "message 1";

Communicator alice("Alice");

// Alice prepares her key and parameters
alice.prepare_key(promised_bit_l, promised_bit_n);

// Alice prepares her message, 
alice.prepare_msg(msg_1);
alice.generate_sig(promised_bit_l); // and generates signature

// Alice verifies her signature
alice.run_verify(promised_bit_l);
```

### Scentario 6: `__test_self_sign_and_verify_large_toy`

This test is identical to `__test_self_sign_and_verify_small_toy`, with more bits set.

```cpp
const int promised_bit_l = 64;
const int promised_bit_n = 20;

// Rest is identical.
```

### Scentario 7: `__test_sig_and_verify_2048_success`


This is another success scenario with bit length (L, N) of (2048, 256) for p and q. This uses `r**` interfaces (untoyed) which utilizes **OpenSSL DSA container**. If the argument is set to 2048 of `DSA_generate_parameters_ex`, it automatically sets the parameter p and q to 2048 bits and 256 bits each. 

Remember to not to set it *'toyed'*, in order to benefit from the **OpenSSL DSA instance**.


```cpp
const int promised_bit_l = 2048; // Not toyed

const char* msg_1 = "message 3";
const char* msg_2 = "message 3";

Communicator alice("Alice");
Communicator bob("Bob");

// Rest is identical to __test_sig_and_verify_1024_success
```
