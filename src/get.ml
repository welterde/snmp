open Snmp


let handle_value = function
  | Snmp_packet.SMI.Int_Value x -> string_of_int x
  | Snmp_packet.SMI.Str_Value x -> Cstruct.to_string x
  | Snmp_packet.SMI.Timeticks_Value x -> string_of_int x
  | _ -> "unknown"

let main _ =
  lwt t = Snmp.create Sys.argv.(1) Sys.argv.(2) in
  try_lwt
    lwt ret = Snmp.get t (Asn.OID.of_string Sys.argv.(3)) in
    let v = handle_value ret in
    Lwt_io.printf "%s = %s\n" Sys.argv.(3) v
  with
    | Timeout -> Lwt_io.print "Timeout..\n"
    | Not_Same_OID -> Lwt_io.print "Not same OID\n"
    | No_Such_Instance -> Lwt_io.print "No such instance\n"
    | No_Such_Object -> Lwt_io.print "No such object\n"


let () =
  if Array.length Sys.argv < 4 then begin
    print_string "Usage: snmp_get <host> <community> <oid>";
    exit 1
  end
  else
    Lwt_main.run (main ())
    
    
