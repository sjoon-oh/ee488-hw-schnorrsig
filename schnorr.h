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


#ifndef __OPENSSL
#define __OPENSSL
#endif

/* Every API information can be found in the official document:
 *  https://www.openssl.org, specifically https://www.openssl.org/docs/man1.1.1/man3/
 */

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

    const unsigned NPARAMS  = 11;
    const unsigned MAX_SLEN = 90000;
    const unsigned MAX_CLEN = MAX_SLEN + 1;

    enum {
        BN_P = 0x00,    //  0: p
        BN_Q,           //  1: q
        BN_G,           //  2: g, generator
        BN_K,           //  3: k, 
        BN_R,           //  4: r, 
        BN_S,           //  5: s,
        BN_E,           //  6: e, hashed value
        BN_V,           //  7: v,
        BN_NE,          //  8: ne, new e, for verification
        BN_PK,          //  9: pk, public key
        BN_SK,          // 10: sk, secrey key
    };


    struct BigNumberWrapper final {
        BIGNUM* actor;
        
        BigNumberWrapper();
        BigNumberWrapper(const BigNumberWrapper&);
        BigNumberWrapper(const BigNumberWrapper&&);
        ~BigNumberWrapper();

        BigNumberWrapper& operator =(const BigNumberWrapper&);
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
        bool toy_enable, 
            sk_ready,
            pk_ready, 
            msg_ready, 
            sign_ready;

        // SHA256_CTX sha_context;
        unsigned char sha_digest[SHA256_DIGEST_LENGTH] = { 0, };

        unsigned char mstr[MAX_CLEN] = { 0, };

        /* 
         * Inner interface 
         *  Toy series: prefix 't'
         *  Real series: prefix 'r'
         */
        int do_rkeygen(const int);             // Real
        int do_tkeygen(const int, const int);  // Toy
        
        BIGNUM* do_rhash();                         // Uses registered string
        BIGNUM* do_rhash(const char*);
        BIGNUM* do_rhash(std::string);

        BIGNUM* do_thash(const int);
        BIGNUM* do_thash(const int, const char*);
        BIGNUM* do_thash(const int, std::string);

        int do_sign(const char*);
        int do_sign(std::string);

        void console_msg(const char*, const char*);
        void console_msg(const char*, const std::string&);
        void console_msgn(const char*, const char*);    // Next line?
        void console_msgn(const char*, const std::string&);

        // void console_msgn(const char*, const char*);

    public:
        /* ctor & dtor*/
        SchnorrSignature() : 
            manager(BigNumberManager()), 
            toy_enable(false),
            sk_ready(false),
            pk_ready(false),
            msg_ready(false),
            sign_ready(false) { }
        ~SchnorrSignature() = default;
    
        /* Core Intefaces */
        // int do_rkeygen(const int);             // Real
        // int do_tkeygen(const int, const int);  // Toy

        int do_keygen(const int arg_l, const int arg_n) {
            return toy_enable ? do_tkeygen(arg_l, arg_n) : do_rkeygen(arg_l); 
        };

        int do_regmsg(const char*);
        int do_regmsg(std::string);

        BIGNUM* do_hash(const int arg_n) {
            return toy_enable ? do_thash(arg_n) : do_rhash(); 
        }
        
        BIGNUM* do_hash(const char*) = delete;
        BIGNUM* do_hash(std::string&) = delete;
        
        int do_sign(const int);
        int do_verify(const int);

        int do_reset();

        /* 
         * Getters, inline */
        const unsigned char* get_mstr() { return this->mstr; }
        // const SHA256_CTX get_sha_context() { return this->sha_context; }
        const unsigned char* get_sha_digest() { return this->sha_digest; }

        const BIGNUM* get_signature_s() { return manager.get_asset(BN_S); }
        const BIGNUM* get_signature_e() { return manager.get_asset(BN_E); }

        const bnm_t* get_manager() const { return &manager; } // General

        const BIGNUM* get_p() { return manager.get_asset(BN_P); }
        const BIGNUM* get_q() { return manager.get_asset(BN_Q); }
        const BIGNUM* get_g() { return manager.get_asset(BN_G); }

        const BIGNUM* get_pk() { return manager.get_asset(BN_PK); }

        /* Setters */
        bool set_toy(bool arg_toy) { return (toy_enable = arg_toy); };

        void set_signature_s(BIGNUM* arg_s) { manager.set_asset(arg_s, BN_S); }
        void set_signature_e(BIGNUM* arg_e) { manager.set_asset(arg_e, BN_E); }

        inline void set_signature_pair(BIGNUM* arg_s, BIGNUM* arg_e) {
            set_signature_s(arg_s);
            set_signature_e(arg_e);

            sign_ready = true;
        }

        void set_pqg(BIGNUM* arg_p, BIGNUM* arg_q, BIGNUM* arg_g) {
            manager.set_asset(arg_p, BN_P);
            manager.set_asset(arg_q, BN_Q);
            manager.set_asset(arg_g, BN_G);
        }

        void set_pk(BIGNUM* arg_pk) { 
            manager.set_asset(arg_pk, BN_PK); 
            pk_ready = true;
        }

        /* Validation Checker */
        inline const bool is_toy() { return this->toy_enable; }
        inline const bool is_sk_ready() { return this->sk_ready; }
        inline const bool is_pk_ready() { return this->pk_ready; }
        inline const bool is_msg_ready() { return this->msg_ready; }
        inline const bool is_sign_ready() { return this->sign_ready; }
    
    private:
        void do_show_assets(); // Inaccessible, for now.
    };
};
