type t = {
  version : string ;
  application_id : string ;
}

let create application_id =
  { version = "U2F_V2" ; application_id }

type protocol_error =
  [ `Other_error | `Bad_request | `Configuration_unsupported
  | `Device_ineligible | `Timeout | `Unrecognized of int ]

let pp_protocol_error ppf = function
  | `Other_error -> Format.pp_print_string ppf "other error"
  | `Bad_request -> Format.pp_print_string ppf "bad request"
  | `Configuration_unsupported ->
    Format.pp_print_string ppf "configuration unsupported"
  | `Device_ineligible ->
    Format.pp_print_string ppf "device ineligible"
  | `Timeout -> Format.pp_print_string ppf "timeout reached"
  | `Unrecognized n -> Format.fprintf ppf "unrecognized %d" n

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

let pp_error ppf = function
  | `Protocol p -> pp_protocol_error ppf p
  | `Json_decoding (name, err, value) ->
    Format.fprintf ppf "json decoding of %s failed with %S (input %S)"
      name err value
  | `Base64_decoding (name, err, value) ->
    Format.fprintf ppf "base64 decoding of %s failed with %S (input %S)"
      name err value
  | `Binary_decoding (name, err, value) ->
    Format.fprintf ppf "binary decoding of %s failed with %S (input %a)"
      name err Cstruct.hexdump_pp (Cstruct.of_string value)
  | `Version_mismatch (expected, received) ->
    Format.fprintf ppf "version mismatch, expected %S, received %S"
      expected received
  | `Typ_mismatch (expected, received) ->
    Format.fprintf ppf "typ mismatch, expected %S, received %S"
      expected received
  | `Challenge_mismatch (expected, received) ->
    Format.fprintf ppf "challenge mismatch, expected %S, received %S"
      expected received
  | `Unknown_key_handle received ->
    Format.fprintf ppf "unknown key handle %S" received
  | `Signature_verification msg ->
    Format.fprintf ppf "signature verification failed %s" msg
  | `Origin_mismatch (expected, received) ->
    Format.fprintf ppf "origin mismatch, expected %S, received %S"
      expected received

type challenge = string

type key_handle = string

let b64_enc = Base64.(encode_string ~pad:false ~alphabet:uri_safe_alphabet)

let lift_err f = function Ok _ as a -> a | Error x -> Error (f x)

let b64_dec thing s =
  lift_err
    (function `Msg m -> `Base64_decoding (thing, m, s))
    Base64.(decode ~pad:false ~alphabet:uri_safe_alphabet s)

type register_request = {
  version : string ;
  challenge : string ;
} [@@deriving yojson]

type registered_key = {
  version : string ;
  keyHandle : string ;
} [@@deriving yojson]

type u2f_register_request = {
  appId : string ;
  registerRequests : register_request list ;
  registeredKeys : registered_key list ;
} [@@deriving yojson]

let challenge () =
  let random = Cstruct.to_string (Mirage_crypto_rng.generate 32) in
  b64_enc random

let register_request ?(key_handles = []) { version ; application_id } =
  let challenge = challenge () in
  let reg_req = {
    appId = application_id ;
    registerRequests = [ { version ; challenge } ] ;
    registeredKeys = List.map (fun keyHandle -> { version ; keyHandle }) key_handles
  } in
  challenge,
  Yojson.Safe.to_string (u2f_register_request_to_yojson reg_req)

let res_typ_to_string = function
  | `Sign -> "navigator.id.getAssertion"
  | `Register -> "navigator.id.finishEnrollment"

let res_typ = function
  | "navigator.id.getAssertion" -> Ok `Sign
  | "navigator.id.finishEnrollment" -> Ok `Register
  | x -> Error (`Msg ("unknown type " ^ x))

type clientData = {
  challenge : string ;
  origin : string ;
  typ : string ;
} [@@deriving yojson]

let error_code_of_int = function
  | 0 -> Ok ()
  | 1 -> Error `Other_error
  | 2 -> Error `Bad_request
  | 3 -> Error `Configuration_unsupported
  | 4 -> Error `Device_ineligible
  | 5 -> Error `Timeout
  | n -> Error (`Unrecognized n)

type u2f_register_response = {
  clientData : string ;
  errorCode : int ;
  registrationData : string ;
  version : string ;
} [@@deriving yojson]

let (>>=) v f = match v with Ok v -> f v | Error _ as e -> e

let guard p e = if p then Ok () else Error e

(* manually extract the certificate length to split <cert> <signature> *)
let seq_len cs =
  let open Rresult.R.Infix in
  guard (Cstruct.get_uint8 cs 0 = 0x30)
    (`Msg "Certificate is not an ASN.1 sequence") >>= fun () ->
  let first_len = Cstruct.get_uint8 cs 1 in
  if first_len > 0x80 then
    let len_bytes = first_len - 0x80 in
    guard (Cstruct.len cs > len_bytes + 2)
      (`Msg "Certificate with too few data") >>= fun () ->
    let rec read_more acc off =
      if off = len_bytes then
        Ok (acc + 2 + len_bytes)
      else
        let v = acc * 256 + Cstruct.get_uint8 cs (off + 2) in
        read_more v (off + 1)
    in
    read_more 0 0
  else
    Ok (first_len + 2)

let decode_reg_data data =
  let cs = Cstruct.of_string data in
  guard (Cstruct.len cs >= 67)
    (`Msg "registration data too small (< 67)") >>= fun () ->
  guard (Cstruct.get_uint8 cs 0 = 0x05)
    (`Msg "registration data first byte must be 0x05") >>= fun () ->
  let pubkey, rest = Cstruct.(split (shift cs 1) 65) in
  let kh_len = Cstruct.get_uint8 rest 0 in
  guard (Cstruct.len rest > kh_len)
    (`Msg ("registration data too small (< kh_len)")) >>= fun () ->
  let kh, rest = Cstruct.(split (shift rest 1) kh_len) in
  seq_len rest >>= fun clen ->
  guard (Cstruct.len rest > clen)
    (`Msg ("registration data too small (< clen)")) >>= fun () ->
  let cert_data, signature = Cstruct.split rest clen in
  X509.Certificate.decode_der cert_data >>= fun cert ->
  match Mirage_crypto_ec.P256.Dsa.pub_of_cstruct pubkey with
  | Ok key -> Ok (key, kh, cert, signature)
  | Error err ->
    let err = Format.asprintf "%a" Mirage_crypto_ec.pp_error err in
    Error (`Msg err)

let verify_sig pub ~signature data =
  match X509.Public_key.verify `SHA256 ~signature pub (`Message data) with
  | Error `Msg m -> Error (`Signature_verification m)
  | Ok () -> Ok ()

let verify_reg_sig cert app client_data kh key signature =
  let h s = Mirage_crypto.Hash.SHA256.digest (Cstruct.of_string s) in
  let data =
    Cstruct.concat [
      Cstruct.create 1 ;
      h app ;
      h client_data ;
      kh ;
      Mirage_crypto_ec.P256.Dsa.pub_to_cstruct key
    ]
  in
  verify_sig (X509.Certificate.public_key cert) ~signature data

let verify_auth_sig key app presence counter client_data signature =
  let data =
    let h s = Mirage_crypto.Hash.SHA256.digest (Cstruct.of_string s) in
    let p_c =
      let b = Cstruct.create 5 in
      if presence then Cstruct.set_uint8 b 0 1;
      Cstruct.BE.set_uint32 b 1 counter;
      b
    in
    Cstruct.concat [ h app ; p_c ; h client_data ]
  in
  verify_sig (`P256 key) ~signature data

let of_json_or_err thing p json =
  lift_err
    (fun msg -> `Json_decoding (thing, msg, Yojson.Safe.to_string json))
    (p json)

let of_json thing p s =
  (try Ok (Yojson.Safe.from_string s)
   with Yojson.Json_error msg ->
     Error (`Json_decoding (thing, msg, s))) >>=
  of_json_or_err thing p

let register_response (t : t) challenge data =
  of_json "RegisterResponse"
    u2f_register_response_of_yojson data >>= fun reg_resp ->
  lift_err (fun p -> `Protocol p)
    (error_code_of_int reg_resp.errorCode) >>= fun () ->
  guard (String.equal t.version reg_resp.version)
    (`Version_mismatch (t.version, reg_resp.version)) >>= fun () ->
  b64_dec "clientData" reg_resp.clientData >>= fun client_data_json ->
  b64_dec "registrationData" reg_resp.registrationData >>= fun reg_data ->
  lift_err
    (function `Msg m -> `Binary_decoding ("registrationData", m, reg_data))
    (decode_reg_data reg_data) >>= fun (key, key_handle, certificate, signature) ->
  of_json "clientData" clientData_of_yojson client_data_json >>= fun client_data ->
  guard (res_typ client_data.typ = Ok `Register)
    (`Typ_mismatch (res_typ_to_string `Register, client_data.typ)) >>= fun () ->
  guard (String.equal challenge client_data.challenge)
    (`Challenge_mismatch (challenge, client_data.challenge)) >>= fun () ->
  verify_reg_sig certificate t.application_id client_data_json
    key_handle key signature >>= fun () ->
  Ok (key, b64_enc (Cstruct.to_string key_handle), certificate)

type u2f_authentication_request = {
  appId : string ;
  challenge : string ;
  registeredKeys : registered_key list ;
} [@@deriving yojson]

let authentication_request { version ; application_id } key_handles =
  let challenge = challenge () in
  let ar = {
    appId = application_id ;
    challenge ;
    registeredKeys = List.map (fun keyHandle -> { version ; keyHandle }) key_handles
  } in
  challenge,
  Yojson.Safe.to_string (u2f_authentication_request_to_yojson ar)

type u2f_authentication_response = {
  clientData : string ;
  errorCode : int ;
  keyHandle : string ;
  signatureData : string ;
} [@@deriving yojson]

let decode_sigdata data =
  let cs = Cstruct.of_string data in
  guard (Cstruct.len cs > 5)
    (`Msg "sigData too small") >>= fun () ->
  let user_presence = Cstruct.get_uint8 cs 0 = 1 in
  let counter = Cstruct.BE.get_uint32 cs 1 in
  let signature = Cstruct.shift cs 5 in
  Ok (user_presence, counter, signature)

let authentication_response (t : t) key_handle_keys challenge data =
  of_json "AuthenticationResponse"
    u2f_authentication_response_of_yojson data >>= fun sig_resp ->
  lift_err (fun p -> `Protocol p)
    (error_code_of_int sig_resp.errorCode) >>= fun () ->
  b64_dec "clientData" sig_resp.clientData >>= fun client_data_json ->
  b64_dec "signatureData" sig_resp.signatureData >>= fun sigdata ->
  lift_err
    (function `Msg m -> `Binary_decoding ("signatureData", m, sigdata))
    (decode_sigdata sigdata) >>= fun (user_present, counter, signature) ->
  of_json "clientData"
    clientData_of_yojson client_data_json >>= fun client_data ->
  guard (res_typ client_data.typ = Ok `Sign)
    (`Typ_mismatch (res_typ_to_string `Sign, client_data.typ)) >>= fun () ->
  guard (String.equal challenge client_data.challenge)
    (`Challenge_mismatch (challenge, client_data.challenge)) >>= fun () ->
  guard (String.equal t.application_id client_data.origin)
    (`Origin_mismatch (t.application_id, client_data.origin)) >>= fun () ->
  List.fold_left (fun acc (_, pubkey) ->
    match acc with
    | Ok key -> Ok key
    | Error _ ->
      verify_auth_sig pubkey t.application_id user_present counter
        client_data_json signature >>= fun () ->
      Ok pubkey)
   (Error (`Unknown_key_handle sig_resp.keyHandle))
   (List.filter (fun (kh, _) -> String.equal kh sig_resp.keyHandle) key_handle_keys)
  >>= fun pubkey ->
  Ok ((sig_resp.keyHandle, pubkey), user_present, counter)

