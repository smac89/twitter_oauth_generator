/* liboauthsign.h - include file for liboauthsign */

/* Signs an OAuth request.
**
** On success, returns a malloc()ed string containing the authorization
** header.
**
** On failure, returns a (char*) 0.
*/
char* oauth_sign( int query_mode, char* consumer_key, const char* consumer_key_secret, char* token, const char* token_secret, const char* method, const char* url, int paramc, char** paramv );

/* If this is called before oauth_sign(), then the Signature Base String
** will get written to stderr as a debugging aid.
*/
void oauth_show_sbs( void );

typedef struct OauthBuilder Builder;

Builder* new_oauth_builder( void );
void set_consumer_key(Builder*, const char *);
void set_consumer_secret(Builder*, const char *);
void set_token(Builder*, const char *);
void set_token_secret(Builder*, const char *);
void set_method(Builder*, const char *);
void set_url(Builder*, const char *);
void set_url_params(Builder *builder, const char** params, int len);
void destroy_builder(Builder **builder);
const char* get_signature(const Builder* builder);
