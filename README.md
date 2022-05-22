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

The class `SchnorrSignature` contains single `BigNumberManager`. All inner functions requests modification of the values using its `BigNumberManager` typed member, `manager`. 

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
- `do_keygen` : 
- `do_regmsg` : 
- `do_hash` : 
- `do_sign` : 
- `do_verify` : 
- `do_reset` : 

Other interfaces are just setters and getters, thus will not be explained here in detail.