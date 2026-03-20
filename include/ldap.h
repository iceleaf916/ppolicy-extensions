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

#define LDAP_SUCCESS 0

#define LDAP_CONSTRAINT_VIOLATION 0x13

/* Mock function declarations */
int ldap_initialize(LDAP** ld, const char* uri);
int ldap_simple_bind_s(LDAP* ld, const char* dn, const char* passwd);
int ldap_search_ext_s(LDAP* ld, const char* base, int scope, const char* filter,
                      char** attrs, int attrsonly, void* controls, void* serverctrls,
                      void* timeout, int sizelimit, LDAPMessage** results);
int ldap_get_attribute_values(LDAP* ld, LDAPMessage* entry, const char* attr,
                              char*** values);
void ldap_msgfree(LDAPMessage* msg);
int ldap_unbind(LDAP* ld);

#endif /* LDAP_H */
