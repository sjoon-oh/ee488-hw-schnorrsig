/* Author: SukJoon Oh
 * Environment: 
 *      Manjaro Quonos 21.2, 
 *      g++ (GCC) 11.2.0,
 *      OpenSSL 1.1.1n (comes default in coreutils)
 * Compilation Option: -lssl -lcrypto
 *      Refer to Makefile for more information.
 * Legal Stuff: None
 */

#ifndef __OPENSSL
#define __OPENSSL
#endif

#ifdef __OPENSSL
#define OPENSSL_API_COMPAT  0x10101000L

#include <openssl/dsa.h>
#include <openssl/engine.h>

#include <openssl/bn.h>     // Big number lib
#include <openssl/sha.h>    // SHA256 lib

#endif

#include <chrono>
#include <vector>


namespace EE488 {

    const unsigned NPARAMS  = 10;
    const unsigned MAX_SLEN = 90000;
    const unsigned MAX_CLEN = MAX_SLEN + 1;

    enum {
        BN_P = 0x00,    // 0: p
        BN_Q,           // 1: q
        BN_G,           // 2: g, generator
        BN_K,           // 3: k, NOT USED
        BN_R,           // 4: r, 
        BN_S,           // 5: s,
        BN_E,           // 6: e, hashed value
        BN_T,           // 7: t, reserved for temporary-use, NOT USED
        BN_PK,          // 8: pk, public key
        BN_SK,          // 9: sk, secrey key
    };


    struct BigNumberWrapper final {
        BIGNUM* actor;
        
        BigNumberWrapper();
        ~BigNumberWrapper();

        BigNumberWrapper& operator =(BigNumberWrapper) = delete;
        BigNumberWrapper(BigNumberWrapper&) = delete;
        BigNumberWrapper(BigNumberWrapper&&) = delete;
    };

    using bnw_t = BigNumberWrapper;


    /* 
     * class BigNumberManager 
     */
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


    /* 
     * class SchnorrSignature 
     */
    class SchnorrSignature {
    private:
        bnm_t manager;
        bool key_ready, msg_ready, sign_ready;

        SHA256_CTX sha_context;
        unsigned char sha_digest[SHA256_DIGEST_LENGTH] = { 0, };

        unsigned char mstr[MAX_CLEN] = { 0, };

    // Inner interface
        int do_hash(const char*);
        int do_hash(std::string);

        int do_sign(const char*);
        int do_sign(std::string);

    public:
        SchnorrSignature() : 
            manager(BigNumberManager()), 
            key_ready(false),
            msg_ready(false),
            sign_ready(false) { }
        ~SchnorrSignature() = default;
    
        /* Core Intefaces */
        int do_keygen();
        int do_regmsg(const char*);
        int do_regmsg(std::string);

        int do_hash();
        int do_sign();
        int do_verify();

        int do_reset();

        /* Getters */
        const unsigned char* get_mstr() { return this->mstr; }
        const SHA256_CTX get_sha_context() { return this->sha_context; }
        const unsigned char* get_sha_digest() { return this->sha_digest; }

        const BIGNUM* get_signature_s() { return manager.get_asset(BN_S); }
        const BIGNUM* get_signature_e(){ return manager.get_asset(BN_E); }

        /* Validation Checker */
        const bool is_key_ready() { return this->key_ready; }
        const bool is_msg_ready() { return this->msg_ready; }
        const bool is_sign_ready() { return this->sign_ready; }
    
    private:
        void do_show_assets(); // Inaccessible, for now.
    };
};