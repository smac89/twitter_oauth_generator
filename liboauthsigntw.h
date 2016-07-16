#ifndef LIB_TWITTER_OAUTH_SIGN_H
#define LIB_TWITTER_OAUTH_SIGN_H

typedef struct OauthBuilder Builder;

Builder *new_oauth_builder(void);

void set_consumer_key(Builder *, const char *);

void set_consumer_secret(Builder *, const char *);

void set_token(Builder *, const char *);

void set_token_secret(Builder *, const char *);

void set_http_method(Builder *, const char *);

void set_base_url(Builder *, const char *);

void set_request_params(Builder *builder, const char **params, int len);

void destroy_builder(Builder **builder);

const char *get_header_string(Builder *builder);

#endif /*TWITTER_OAUTH_SIGN_H*/
