#ifndef LIB_TWITTER_OAUTH_SIGN_TW_H
#define LIB_TWITTER_OAUTH_SIGN_TW_H

typedef struct OauthBuilder Builder;

/**
 * @brief      Creates a new builder object
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
void set_consumer_key(Builder *, const char *);

/**
 * @brief      Sets the consumer secret.
 *
 * @param      builder  The builder
 * @param[in]  key      The secret
 */
void set_consumer_secret(Builder *, const char *);

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
void set_token(Builder *, const char *);

/**
 * @brief      Sets the token secret.
 *
 * @param      builder  The builder
 * @param[in]  key      The token secret
 */
void set_token_secret(Builder *, const char *);

/**
 * @brief      Sets the http method.
 *
 * @details    The request method will almost always be GET or POST
 * for Twitter API requests.
 *
 * @param      builder  The builder
 * @param[in]  key      The http method
 */
void set_http_method(Builder *, const char *);

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
void set_base_url(Builder *, const char *);

/**
 * @brief      Sets the request parameters.
 *
 * @param      builder  The builder
 * @param      params   The parameters
 * @param[in]  length    The length
 */
void set_request_params(Builder *builder, const char **params, int len);

/**
 * @brief      Gets the header string.
 *
 * @param[in]  builder  The builder with all the required parameters
 *
 * @return     The header string.
 */
const char *get_header_string(Builder *builder);

/**
 * @brief      Destroys a builder.
 *
 * @param      builder  The builder
 * @pre        Must not be null and must have been created by new_oauth_builder()
 */
void destroy_builder(Builder **builder);

#endif /*LIB_TWITTER_OAUTH_SIGN_TW_H*/
