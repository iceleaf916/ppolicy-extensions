/* Mock LDAP header for compilation without OpenLDAP dev packages */
#ifndef LDAP_H
#define LDAP_H

#include <sys/types.h>

/* Basic LDAP types */
typedef struct LDAP {
    int ld_version;
    void* ld;
} LDAP;

typedef struct LDAPMessage LDAPMessage;

/* berval structure (normally from lber.h) */
#ifndef LBER_H
typedef struct berval {
    unsigned long bv_len;
    char* bv_val;
} BerValue;
#endif

/* LDAP result codes */
#define LDAP_SUCCESS 0
#define LDAP_CONSTRAINT_VIOLATION 0x13

/* LDAP options */
#define LDAP_OPT_PROTOCOL_VERSION 0x0011

/* LDAP search scopes */
#define LDAP_SCOPE_BASE 0x0000

/* Mock function declarations */
int ldap_initialize(LDAP** ld, const char* uri);
int ldap_set_option(LDAP* ld, int option, const void* invalue);
int ldap_sasl_bind_s(LDAP* ld, const char* dn, const char* mechanism,
                     struct berval* cred, void* sctrls, void* cctrls,
                     struct berval** servercredp);
int ldap_simple_bind_s(LDAP* ld, const char* dn, const char* passwd);
int ldap_search_ext_s(LDAP* ld, const char* base, int scope, const char* filter,
                      char** attrs, int attrsonly, void* controls, void* serverctrls,
                      void* timeout, int sizelimit, LDAPMessage** results);
LDAPMessage* ldap_first_entry(LDAP* ld, LDAPMessage* result);
struct berval** ldap_get_values_len(LDAP* ld, LDAPMessage* entry, const char* attr);
void ldap_value_free_len(struct berval** vals);
int ldap_get_attribute_values(LDAP* ld, LDAPMessage* entry, const char* attr,
                              char*** values);
void ldap_msgfree(LDAPMessage* msg);
int ldap_unbind(LDAP* ld);
int ldap_unbind_ext_s(LDAP* ld, void* sctrls, void* cctrls);

#endif /* LDAP_H */
