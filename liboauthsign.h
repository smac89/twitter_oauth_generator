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
typedef void (*BuilderMethod) (Builder*, const char *);


Builder* new_oauth_builder();
BuilderMethod set_consumer_key;
BuilderMethod set_consumer_secret;
BuilderMethod set_method;
BuilderMethod set_url;
void destroy_builder(Builder *builder);
const char* get_signature(const Builder* builder);
