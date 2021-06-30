(** U2F - Universal Second Factor

    U2F is a standard for two-factor authentication with special USB or NFC
    devices. A challenge-response authentication with the device using public
    key cryptography is done.

    This library is stateless, a client of this API has to preserve challenges
    (for register/authentication session), and for each registered device a
    quadruple of key handle, public key, certificate, and counter.

    A common use of this module is that on startup a {!t} is created. For a
    registration, first {!register_request} is called (the challenge is
    preserved, the data is sent to the client), and {!register_response} is
    called with the client response (and the same challenge). If the
    verification succeeds, the client information (public key, key handle) is
    returned.
    To authenticate the function {!authentication_request} is called with the
    non-empty list of registered key handles. The resulting challenge is
    preserved, the data is sent to the client. Upon a response from the client,
    {!authentication_response} should be called with the association list of
    key handle and public key, the challenge, and the client response.
*)

(** The type of a u2f state, containing the version string and application ID. *)
type t

(** [create application_id] creates a u2f state with the provided application
    ID. The application ID is not validated. *)
val create : string -> t

(** The type of protocol errors, as specified by the standard. *)
type protocol_error =
  [ `Other_error | `Bad_request | `Configuration_unsupported
  | `Device_ineligible | `Timeout | `Unrecognized of int ]

(** [pp_protocol_error ppf error] pretty-prints the protocol [error] on
    [ppf]. *)
val pp_protocol_error : Format.formatter -> protocol_error -> unit

(** The type of errors when verifying client responses. *)
type error = [
  | `Protocol of protocol_error
  | `Json_decoding of string * string * string
  | `Base64_decoding of string * string * string
  | `Binary_decoding of string * string * string
  | `Version_mismatch of string * string
  | `Typ_mismatch of string * string
  | `Challenge_mismatch of string * string
  | `Unknown_key_handle of string
  | `Signature_verification of string
  | `Origin_mismatch of string * string
]

(** [pp_error ppf error] pretty-prints the [error] on [ppf]. *)
val pp_error : Format.formatter -> error -> unit

(** The type alias of a challenge. *)
type challenge = string

(** The type alias of a key handle. *)
type key_handle = string

(** [register_request ~key_handles t] results in a challenge and data to be
    sent to the client. The [key_handles] should be the already registered
    key handles for this account. The [challenge] is randomly generated, and
    unique for this session. It must be passed to {!register_response}. *)
val register_request : ?key_handles:key_handle list -> t -> challenge * string

(** [register_response t challenge client_data] verifies the [client_data] with
    the provided [challenge], and data in [t] (application ID, version).
    On success, a tuple of public key, key handle, and certificate is returned.
    On error, the specific error is returned. *)
val register_response : t -> challenge -> string ->
  (Mirage_crypto_ec.P256.Dsa.pub * key_handle * X509.Certificate.t,
   error) result

(** [authentication_request t key_handles] randomly generates a challenge,
    and returns both the challenge (unique for this session, should be
    preserved and must be passed to {!authentication_response}), and the data
    to be sent to the client. *)
val authentication_request : t -> key_handle list ->
  challenge * string

(** [authentication_response t key_handle_pub challenge client_data] verifies
    the [client_data] using the [challenge] and looks it up in the
    [key_handle_pub] associative list. If successful, the used key handle and
    public key is returned, also a boolen whether the user was present, and the
    counter - an unsigned 32 bit integer. The counter should be verified to
    be strictly monotonically increasing for the key handle and public key. *)
val authentication_response : t ->
  (key_handle * Mirage_crypto_ec.P256.Dsa.pub) list ->
  challenge -> string ->
  ((key_handle * Mirage_crypto_ec.P256.Dsa.pub) * bool * int32, error) result
