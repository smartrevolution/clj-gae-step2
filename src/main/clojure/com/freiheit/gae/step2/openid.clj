;; Copyright (c) 2010 freiheit.com technologies gmbh
;; 
;; This file is part of clj-gae-step2.
;; clj-gae-step2 is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; clj-gae-step2 is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.

;; You should have received a copy of the GNU Lesser General Public License
;; along with clj-gae-step2.  If not, see <http://www.gnu.org/licenses/>.

(ns com.freiheit.gae.step2.openid
  (:use
   [clojure.contrib.def]
   [clojure.contrib.str-utils :only [re-gsub]])
  (:import
   [com.google.inject AbstractModule Guice]
   [com.google.step2 AuthRequestHelper ConsumerHelper AuthResponseHelper AuthResponseHelper$ResultType Step2$AxSchema]
   [com.google.step2.discovery IdpIdentifier]
   [com.google.step2.example.consumer GuiceModule]
   [org.openid4java.message ParameterList]))


;;;; Authentication via OpenID. Uses the Step2 library to perform the
;;;; authentication.

;; ------------------------------------------------------------------------------
;; data structures and constants
;; ------------------------------------------------------------------------------

(defn- get-consumer-helper
  []
  (-> (Guice/createInjector (into-array [(GuiceModule.)]))
      (.getInstance ConsumerHelper)))

(defvar- *consumer-helper* (get-consumer-helper))


;; ------------------------------------------------------------------------------
;; private functions
;; ------------------------------------------------------------------------------

(defn- get-identifier
  [e-mail]
  (IdpIdentifier. e-mail))

(defn- map-with-str-keys
  [m]
  (->> m
       (map (fn [[k v]] [(name k) v]))
       (into {})))

(defn- get-auth-response
  [#^IMap response-params]
  (ParameterList. (map-with-str-keys response-params)))

(defn- auth-success?
  [#^AuthResponseHelper auth-response-helper]
  (= (.getAuthResultType auth-response-helper)
     AuthResponseHelper$ResultType/AUTH_SUCCESS))

(defn- user-identity
  [#^AuthResponseHelper auth-response-helper]
  {:endpoint (str (.. auth-response-helper getAuthResponse getOpEndpoint))
   :claimed-id (str (.. auth-response-helper (getClaimedId) (getIdentifier)))
   :e-mail (.getAxFetchAttributeValue auth-response-helper Step2$AxSchema/EMAIL)
   :first-name (.getAxFetchAttributeValue auth-response-helper Step2$AxSchema/FIRST_NAME)
   :last-name (.getAxFetchAttributeValue auth-response-helper Step2$AxSchema/LAST_NAME)})

(defn- set-realm!
  [auth-request realm]
  (.setRealm auth-request realm)
  auth-request)

(defn- auth-information
  [#^AuthRequestHelper auth-request-helper realm]
  {:destination-url (-> (.generateRequest auth-request-helper)
                        (set-realm! realm)
                        (.getDestinationUrl true))
   :discovery-information (.getDiscoveryInformation auth-request-helper)})

(defn with-ax-requests
  [auth-request-helper ax-schema]
  (.requestAxAttribute auth-request-helper 
                       (.getShortName ax-schema) 
                       (.getUri ax-schema) true 1))

;; ------------------------------------------------------------------------------
;; public functions
;; ------------------------------------------------------------------------------

(defn extract-domain-from-email
  "Extract the domain part from an email address. The domain is used to determine
   the OpenID Identity Provider (IDP)."
  [email]
  (re-gsub #".*@" "" email))

(defn openid-auth-information
  "Return the authentication information for the given domain. This information
   contains the destination URL (the OpenID client must redirect to this url in order
   to start the authentication request) and discovery information (claimed and delegated
   identifiers, endpoint, protocol versions etc.)."
  [#^String domain #^String return-url #^String realm]
  (let [consumer-helper *consumer-helper*
        identifier (get-identifier domain)
        auth-request-helper (-> (.getAuthRequestHelper consumer-helper 
                                                       identifier return-url)
                                (with-ax-requests Step2$AxSchema/EMAIL)
                                (with-ax-requests Step2$AxSchema/FIRST_NAME)
                                (with-ax-requests Step2$AxSchema/LAST_NAME))]
    (auth-information auth-request-helper realm)))

(defn openid-user-identity
  "Verify the parameters from the authentification response from the OpenID Provider
   and return the available information for the authentificated user. The discovery
   information adds information about claimed id, delegated id, endpoint, protocol
   versions etc. for additional security but can also be nil to skip the discovery
   information validation.
   
   Returns nil if the authentification process failed."
  [#^String receiving-url #^IMap openid-xrds-params discovery-information]
  (let [consumer-helper *consumer-helper*
        auth-response (get-auth-response openid-xrds-params)
        auth-response-helper (.verify consumer-helper
                                      receiving-url
                                      auth-response
                                      discovery-information)]
    (if (auth-success? auth-response-helper)
      (user-identity auth-response-helper))))
