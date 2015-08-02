
let handle_value = function
  | Packet.SMI.Int_Value x -> string_of_int x
  | Packet.SMI.Timeticks_Value x -> string_of_int x
  | _ -> "unknown"

let handle_varbind (oid, x) =
  let v = match x with
    | `NoSuchInstance -> "no such instance"
    | `NoSuchObject -> "no such object"
    | `Unspecified -> "unspec"
    | `EndOfMIBView -> "end of MIB"
    | `Value vv -> Printf.sprintf "value %s" (handle_value vv)
  in Lwt_io.printf "%s=%s\n" (Asn.OID.to_string oid) v

let handle_response pdu =
  lwt _ = Lwt_io.print "Response!\n" in
  if List.length pdu.Packet.PDU.variable_bindings > 0 then
    handle_varbind (List.hd pdu.Packet.PDU.variable_bindings)
  else
    Lwt.return_unit

let main _ =
  lwt t = Snmp.create Sys.argv.(1) Sys.argv.(2) in
  lwt ret = Snmp.get t (Asn.OID.of_string Sys.argv.(3)) in
  match ret with
    | `Timeout -> Lwt_io.print "Timeout..\n"
    | `Response pdu -> handle_response pdu


let () =
  if Array.length Sys.argv < 4 then begin
    print_string "Usage: snmp_get <host> <community> <oid>";
    exit 1
  end
  else
    Lwt_main.run (main ())
    
    
