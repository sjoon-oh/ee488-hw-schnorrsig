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
        bool key_ready, msg_ready, sign_ready, veri_ready;

        SHA256_CTX sha_context;
        unsigned char sha_digest[SHA256_DIGEST_LENGTH] = { 0, };

        unsigned char mstr[MAX_CLEN] = { 0, };

        /* Inner interface */
        int do_hash(const char*);
        int do_hash(std::string);

        int do_sign(const char*);
        int do_sign(std::string);

    public:
        SchnorrSignature() : 
            manager(BigNumberManager()), 
            key_ready(false),
            msg_ready(false),
            sign_ready(false),
            veri_ready(false) { }
        ~SchnorrSignature() = default;
    
        /* Core Intefaces */
        int do_keygen_r(const int);             // Real
        int do_keygen_t(const int, const int);  // Toy

        int do_regmsg(const char*);
        int do_regmsg(std::string);

        int do_hash();
        int do_sign();
        int do_verify();

        int do_reset();

        /* 
         * Getters */
        const unsigned char* get_mstr() { return this->mstr; }
        const SHA256_CTX get_sha_context() { return this->sha_context; }
        const unsigned char* get_sha_digest() { return this->sha_digest; }

        const BIGNUM* get_signature_s() { return manager.get_asset(BN_S); }
        const BIGNUM* get_signature_e() { return manager.get_asset(BN_E); }

        const bnm_t* get_manager() const { return &manager; }

        /* Setters */
        void set_signature_s(BIGNUM* arg_s) { manager.set_asset(arg_s, BN_S); }
        void set_signature_e(BIGNUM* arg_e) { manager.set_asset(arg_e, BN_E); }

        inline void set_signature_pair(BIGNUM* arg_s, BIGNUM* arg_e) {
            set_signature_s(arg_s);
            set_signature_e(arg_e);

            veri_ready = true;
        }

        /* Validation Checker */
        inline const bool is_key_ready() { return this->key_ready; }
        inline const bool is_msg_ready() { return this->msg_ready; }
        inline const bool is_sign_ready() { return this->sign_ready; }
        inline const bool is_veri_ready() { return this->veri_ready; }
    
    private:
        void do_show_assets(); // Inaccessible, for now.
    };
};
