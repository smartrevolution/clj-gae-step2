About clj-gae-step2
===================

This library is a [Clojure](http://clojure.org) wrapper for the
[step2](http://code.google.com/p/step2) library, a Java implementation
of a hybrid protocol to combine the OpenID authentication and the
OAuth authorization protocols.


IDP Discovery
-------------

Here is an example for a [Compojure](http://compojure.org) request
handler that performs the OpenID discovery and responds with the
information from the XRDS document:

    (defn start-openid-handler
      [request]
      (let [domain (get-in request [:params :domain])
            destination-url "http://example.com/auth"
            realm "http://example.com"
            auth-info (openid/openid-auth-information domain destination-url realm)]
        (store-in-session! request (:discovery-information auth-info))
        (redirect-to (:destination-url auth-info))))

The domain for the OpenID provider (IDP) is given as request
parameter. The auth-info containes two fields, one for the discovery
information that is saved in the current session and will be used to
verify the OpenID authentification. This contains informations about the
OpenID discovery endpoint, used protocol versions etc. The other field
in auth-info is the destination URL, the URL to request the login
authorization.


OpenID Authentification
-----------------------

Here is an example for the request handler to complete the OpenID
authorization that returns the user's identity:

    (defn complete-openid-handler
      [request]
      (let [receiving-url "http://example.com/auth"
            discovery-information (extract-discovery-information-from-session)
            auth-account (openid/openid-user-identity receiving-url
                                                      (:params request)
                                                      discovery-information)]
        (login (:claimed-id auth-account))))

To verify the user authorization the receiving URL of the
complete-openid-handler as well as the discovery information from
the session and the request parameters are required. The verified
auth-account contains the user's OpenID and, if available, his
e-mail address, first name and last name.
