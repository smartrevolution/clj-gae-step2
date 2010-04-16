(ns com.freiheit.gae.step2.openid
  (:use
   [clojure.contrib.def]
   [clojure.contrib.str-utils :only [re-gsub]])
  (:import
   [com.google.inject AbstractModule Guice]
   [com.google.step2 AuthRequestHelper ConsumerHelper]
   [com.google.step2.discovery IdpIdentifier]
   [com.google.step2.example.consumer GuiceModule]))


;;;; Authentication via OpenID. Uses the Step2 library to perform the
;;;; authentication.

;; ------------------------------------------------------------------------------
;; private functions
;; ------------------------------------------------------------------------------

(defn- get-consumer-helper
  []
  (-> (Guice/createInjector (into-array [(GuiceModule.)]))
      (.getInstance ConsumerHelper)))

(defvar- *consumer-helper* (get-consumer-helper))

(defn- get-identifier
  [e-mail]
  (IdpIdentifier. e-mail))

;; ------------------------------------------------------------------------------
;; public functions
;; ------------------------------------------------------------------------------

(defn openid-auth-url
  "Return the authentication url for the given claimed id. The OpenID client 
   must redirect to this url in order to start the authentication request."
  [claimed-id return-url]
  (let [consumer-helper *consumer-helper*
        domain (re-gsub #".*@" "" claimed-id)
        identifier (get-identifier domain)
        auth-request-helper (.getAuthRequestHelper consumer-helper identifier return-url)]
    (.getDestinationUrl (.generateRequest auth-request-helper) true)))