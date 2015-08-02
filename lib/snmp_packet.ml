open Asn

(* Documentation: *)
(* https://tools.ietf.org/html/rfc1905 *)
(* https://tools.ietf.org/html/rfc2578 *)

type 'a t = {
  version : int;
  community : Cstruct.t;
  data : 'a
}

let message data =
  let decode (a,b,c) = {version=a; community=b; data=c}
  and encode x = (x.version, x.community, x.data)
  in map decode encode @@
  sequence3 (required ~label:"version" int) (required ~label:"community" octet_string) (required ~label:"data" data)

    
module SMI = struct

  type t =
    | Int_Value of int
    | Str_Value of Cstruct.t
    | OID_Value of Asn.OID.t
    | IP_Address of Cstruct.t
    | Counter32_Value of int
    | Timeticks_Value of int
    | Counter64_Value of int
    | Unsigned_Int_Value of int
    | Arbitrary_Value of Cstruct.t
    
  let simple_syntax =
    choice3
      int
      octet_string
      oid

  let ip_address =
    implicit ~cls:`Application 0 octet_string

  let counter32 =
    implicit ~cls:`Application 1 int

  let gauge32 =
    implicit ~cls:`Application 2 int

  let unsigned32 =
    implicit ~cls:`Application 2 int

  let timeticks =
    implicit ~cls:`Application 3 int

  let opaque =
    implicit ~cls:`Application 4 octet_string

  let counter64 =
    implicit ~cls:`Application 6 int
      
  let application_syntax =
    choice6
      ip_address
      counter32
      timeticks
      opaque
      counter64
      unsigned32

  let object_syntax =
    let decode = function
      | `C1 (`C1 x) -> Int_Value x
      | `C1 (`C2 x) -> Str_Value x
      | `C1 (`C3 x) -> OID_Value x
      | `C2 (`C1 x) -> IP_Address x
      | `C2 (`C2 x) -> Counter32_Value x
      | `C2 (`C3 x) -> Timeticks_Value x
      | `C2 (`C4 x) -> Arbitrary_Value x
      | `C2 (`C5 x) -> Counter64_Value x
      | `C2 (`C6 x) -> Unsigned_Int_Value x
    and encode = function
      | Int_Value x -> `C1 (`C1 x)
      | Str_Value x -> `C1 (`C2 x)
      | OID_Value x -> `C1 (`C3 x)
      | IP_Address x -> `C2 (`C1 x)
      | Counter32_Value x -> `C2 (`C2 x)
      | Timeticks_Value x -> `C2 (`C3 x)
      | Arbitrary_Value x -> `C2 (`C4 x)
      | Counter64_Value x -> `C2 (`C5 x)
      | Unsigned_Int_Value x -> `C2 (`C6 x)
    in
    map decode encode @@
    choice2
      simple_syntax
      application_syntax

end

module Varbind = struct
  type t = Asn.OID.t * [ `EndOfMIBView
  | `NoSuchInstance
  | `NoSuchObject
  | `Unspecified
  | `Value of SMI.t ]
      
  let varbind =
    sequence2
      (required ~label:"name" oid)
      (required
         (
           let decode = function
             | `C1 x -> `Value x
             | `C2 _ -> `Unspecified
             | `C3 _ -> `NoSuchObject
             | `C4 _ -> `NoSuchInstance
             | `C5 _ -> `EndOfMIBView
           and encode = function
             | `Value x -> `C1 x
             | `Unspecified -> `C2 ()
             | `NoSuchObject -> `C3 ()
             | `NoSuchInstance -> `C4 ()
             | `EndOfMIBView -> `C5 ()
           in map decode encode @@
           choice5
           SMI.object_syntax
           null
           (implicit 0 null)
           (implicit 1 null)
           (implicit 2 null)
         ))
end

module PDU = struct
  type t = {
    req_id : int;
    error_status : int;
    error_index : int;
    variable_bindings : Varbind.t list;
  }

  let make req_id varbinds =
    {
      req_id=req_id;
      error_status=0;
      error_index=0;
      variable_bindings=varbinds;
    }
      
  let pdu =
    let decode (a,b,c,d) = {req_id=a; error_status=b; error_index=c; variable_bindings=d}
    and encode x = (x.req_id, x.error_status, x.error_index, x.variable_bindings)
    in
    map decode encode @@
    sequence4
      (required ~label:"request-id" int)
      (required ~label:"error-status" int)
      (required ~label:"error-index" int)
      (required ~label:"variable-bindings" (sequence_of Varbind.varbind))

  
end
  
let pdus =
  let decode = function
    | `C1 x -> `GetRequest x
    | `C2 x -> `Response x
    | `C3 x -> `SetRequest x
  and encode = function
    | `GetRequest x -> `C1 x
    | `Response x -> `C2 x
    | `SetRequest x -> `C3 x
  in
  map decode encode @@
  choice3
    (implicit 0 PDU.pdu)
    (implicit 2 PDU.pdu)
    (implicit 3 PDU.pdu)

let msg_codec = codec ber (message pdus)
    
let parse m =
  let (ret, _) = decode_exn msg_codec m in
  ret

let unparse = encode msg_codec
