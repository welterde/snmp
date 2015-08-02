
open Snmp_packet

module Req_Map = Map.Make(struct type t = int let compare = compare end)
  
type t = {
  fd : Lwt_unix.file_descr;
  sockaddr : Unix.sockaddr;
  buf : Cstruct.t;
  rnd : Random.State.t;
  community : Cstruct.t;
  pending_reqs : [`Response of PDU.t | `Timeout] Lwt_condition.t Req_Map.t Lwt_mvar.t;
  timeout_time : float;
}

let handle_packet s packet =
  match packet.data with
    | `Response pdu ->
      lwt map = Lwt_mvar.take s.pending_reqs in
      lwt _ = Lwt_mvar.put s.pending_reqs map in
      if Req_Map.exists (fun k _ -> k = pdu.PDU.req_id) map then
        (Lwt_condition.signal (Req_Map.find pdu.PDU.req_id map) (`Response pdu);
         Lwt.return_unit)
      else
        Lwt_io.print "Got garbage!\n"
    | _ ->
      Lwt_io.print "Got non-response!\n"

let rec listener s =
  lwt len, srcaddr = Lwt_cstruct.recvfrom s.fd s.buf [] in
  let packet = parse s.buf in
  Lwt.async (fun _ -> handle_packet s packet);
  listener s
  
    
let create hostname community =
  let socket = Lwt_unix.socket Unix.PF_INET Unix.SOCK_DGRAM (Unix.getprotobyname "udp").Unix.p_proto in
  lwt ipaddr_l = (Lwt_unix.gethostbyname hostname) in
  let ipaddr = ipaddr_l.Unix.h_addr_list.(0) in
  let sockaddr = Unix.ADDR_INET (ipaddr, 161) in
  let s = {
    fd=socket;
    sockaddr=sockaddr;
    buf=Cstruct.create 512;
    rnd=Random.State.make_self_init ();
    community=Cstruct.of_string community;
    pending_reqs=Lwt_mvar.create Req_Map.empty;
    timeout_time=2.0;
  } in
  Lwt.async (fun _ -> listener s);
  Lwt.return s

let register_request s req_id =
  let cond = Lwt_condition.create () in
  lwt map = Lwt_mvar.take s.pending_reqs in
  let map = Req_Map.add req_id cond map in
  lwt _ = Lwt_mvar.put s.pending_reqs map in
  Lwt.return cond

let unregister_request s req_id =
  lwt map = Lwt_mvar.take s.pending_reqs in
  let map = Req_Map.remove req_id map in
  Lwt_mvar.put s.pending_reqs map

exception Timeout

exception Invalid_Varbind

exception Not_Same_OID
exception No_Such_Instance
exception End_Of_MIB_View
exception No_Such_Object
exception Unspecified
    
let get s n =
  let req_id = Random.State.bits s.rnd in
  lwt cond = register_request s req_id in
  let pdu = PDU.make req_id [(n, `Unspecified)] in
  let packet = {
    version=1;
    community=s.community;
    data=`GetRequest pdu;
  } in
  let bitstring = unparse packet in
  lwt _ = Lwt_cstruct.sendto s.fd bitstring [] s.sockaddr in
  
  let timeout = Lwt_unix.sleep s.timeout_time in
  ignore @@ Lwt.bind timeout (fun _ -> Lwt_condition.signal cond `Timeout; Lwt.return_unit);
  lwt ret = Lwt_condition.wait cond in
  Lwt.async (fun _ -> unregister_request s req_id);
  match ret with
    | `Timeout -> raise_lwt Timeout
    | `Response pdu ->
      if List.length pdu.PDU.variable_bindings <> 1 then
        raise_lwt Invalid_Varbind
      else
        let (oid,v) = List.nth pdu.PDU.variable_bindings 0 in
        if (Asn.OID.to_string n) <> (Asn.OID.to_string oid) then
          raise_lwt Not_Same_OID
        else
          match v with
            | `Value x -> Lwt.return x
            | `NoSuchInstance -> raise_lwt No_Such_Instance
            | `EndOfMIBView -> raise_lwt End_Of_MIB_View
            | `NoSuchObject -> raise_lwt No_Such_Object
            | `Unspecified -> raise_lwt Unspecified

let set s n v =
  let req_id = Random.State.bits s.rnd in
  lwt cond = register_request s req_id in
  let pdu = PDU.make req_id [(n, `Value v)] in
  let packet = {
    version=1;
    community=s.community;
    data=`SetRequest pdu;
  } in
  let bitstring = unparse packet in
  lwt _ = Lwt_cstruct.sendto s.fd bitstring [] s.sockaddr in
  
  let timeout = Lwt_unix.sleep s.timeout_time in
  ignore @@ Lwt.bind timeout (fun _ -> Lwt_condition.signal cond `Timeout; Lwt.return_unit);
  lwt ret = Lwt_condition.wait cond in
  Lwt.async (fun _ -> unregister_request s req_id);
  Lwt.return ret
