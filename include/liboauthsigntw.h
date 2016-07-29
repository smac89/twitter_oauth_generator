#ifndef LIB_OAUTH_SIGN_TW_H
#define LIB_OAUTH_SIGN_TW_H

typedef struct OauthBuilder Builder;

/**
 * @brief      Creates a new builder object
 * @details    A call to destroy_builder() must follow after making use of this
 * object
 *
 * @return     a builder for collecting the required parameters
 */
Builder *new_oauth_builder(void);

/**
 * @brief      Sets the consumer key.
 *
 * @details    The oauth_consumer_key identifies which application is
 * making the request. Obtain this value from checking the settings
 * page for your application on dev.twitter.com/apps.
 *
 * @example    oauth_consumer_key   xvz1evFS4wEEPTGEFPHBog
 *
 * @param      builder  The builder
 * @param[in]  key      The key
 */
void set_consumer_key(Builder *builder, const char *key);

/**
 * @brief      Gets the consumer key.
 * The user is responsible for freeing the array
 *
 * @param[in]  builder  The builder
 *
 * @return     The consumer key.
 */
char *get_consumer_key(const Builder *builder);

/**
 * @brief      Sets the consumer secret.
 *
 * @param      builder  The builder
 * @param[in]  key      The secret
 */
void set_consumer_secret(Builder *builder, const char *key);

/**
 * @brief      Gets the consumer secret.
 * The user is responsible for freeing the array
 *
 * @param[in]  builder  The builder
 *
 * @return     The consumer secret.
 */
char *get_consumer_secret(const Builder *builder);

/**
 * @brief      Sets the token.
 *
 * @details    The <b>oauth_token</b> parameter typically represents a user’s
 * permission to share access to their account with your application.
 * There are a few authentication requests where this value is not passed
 * or is a different form of token, but those are covered in detail in
 * Obtaining access tokens. For most general-purpose requests, you will use
 * what is referred to as an <b>access token</b>. You can generate a valid
 * access token for your account on the settings page for your application
 * at dev.twitter.com/apps.
 *
 * @example    oauth_token  370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb
 *
 * @param      builder  The builder
 * @param[in]  key      The token
 */
void set_token(Builder *builder, const char *key);

/**
 * @brief      Gets the token.
 * The user is responsible for freeing the array
 *
 * @param[in]  builder  The builder
 *
 * @return     The token.
 */
char *get_token(const Builder *builder);

/**
 * @brief      Sets the token secret.
 *
 * @param      builder  The builder
 * @param[in]  key      The token secret
 */
void set_token_secret(Builder *builder, const char *key);

/**
 * @brief      Gets the token secret.
 * The user is responsible for freeing the array
 *
 * @param[in]  builder  The builder
 *
 * @return     The token secret.
 */
char *get_token_secret(const Builder *builder);

/**
 * @brief      Sets the http method.
 *
 * @details    The request method will almost always be GET or POST
 * for Twitter API requests.
 *
 * @param      builder  The builder
 * @param[in]  key      The http method
 */
void set_http_method(Builder *builder, const char *key);

/**
 * @brief      Gets the http method.
 * The user is responsible for freeing the array
 *
 * @param[in]  builder  The builder
 *
 * @return     The http method.
 */
char *get_http_method(const Builder *builder);

/**
 * @brief      Sets the base url.
 *
 * @details    The base URL is the URL to which the request is directed, <em>minus any
 * query string or hash parameters</em>. It is important to use the correct protocol here,
 * so make sure that the "https://" or "http://" portion of the URL matches the actual
 * request sent to the API. As a best practice, you should always be using
 * "https://" with the Twitter API.
 *
 * @param      builder  The builder
 * @param[in]  key      The url
 */
void set_base_url(Builder *builder, const char *key);

/**
 * @brief      Gets the base url.
 * The user is responsible for freeing the array
 *
 * @param[in]  builder  The builder
 *
 * @return     The base url.
 */
char *get_base_url(const Builder *builder);

/**
 * @brief      Sets the request parameters.
 *
 * @param      builder  The builder
 * @param      params   The parameters
 * @param[in]  length    The length of the parameters
 */
void set_request_params(Builder *builder, const char **params, int length);

/**
 * @brief      Gets the request params.
 * The user is responsible for freeing the pointers within the array as well
 * as the array itself
 *
 * @param[in]  builder  The builder
 *
 * @return     The request params.
 */
char **get_request_params(const Builder *builder);

/**
 * @brief      Gets the header string.
 * The returned string must be freed after use
 *
 * @param      builder  The builder
 *
 * @return     The header string.
 */
char *get_header_string(Builder *builder);

/**
 * @brief      Destroys a builder.
 *
 * @param      builder  The builder
 * @pre        Must not be null and must have been created by new_oauth_builder()
 */
void destroy_builder(Builder **builder);

#endif // LIB_OAUTH_SIGN_TW_H
