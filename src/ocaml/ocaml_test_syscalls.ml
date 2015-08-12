open Ctypes
open Printf
open Syscalls

let read_syscall_num = 0n
let open_syscall_num = 2n
let close_syscall_num = 3n

let rec supply_syscall_footprint state extents = 
  (* This represents whatever process you go through to
     acquire the footprint data from the simulator *)
  let supply_one_footprint extent = ({
      base = extent.base;
      length = extent.length;
      (* do horrible things with pointers for testing purposes *)
      data = Some (bigarray_of_ptr array1
                                   (Nativeint.to_int extent.length)
                                   Bigarray.char
                                   (from_voidp char (ptr_of_raw_address extent.base)));
                                    }) in
  match Syscalls.continue_syscall state (List.map supply_one_footprint extents) with
  | Finished (retval, write_extents) -> Finished (retval, write_extents)
  | MoreDataNeeded (state, extents) -> supply_syscall_footprint state extents


let do_one_syscall env num args =
  let result = Syscalls.start_syscall env num args in
  match result with 
  | MoreDataNeeded (state, extents) ->
     (match supply_syscall_footprint state extents with
     | MoreDataNeeded (_, _) -> assert false
     | x -> x)
  | x -> x

let string_to_bigarray s =
  let bigarr = Bigarray.Array1.create Bigarray.char Bigarray.c_layout ((String.length s) + 1) in begin
      for i = 0 to (String.length s) - 1 do
        bigarr.{i} <- s.[i]
      done;
      bigarr.{(String.length s)} <- '\000';
      bigarr
    end
  
let string_from_bigarray arr =
  let s = String.make (Bigarray.Array1.dim arr) '\000' in begin
      for i = 0 to (Bigarray.Array1.dim arr) - 1 do
        s.[i] <- arr.{i}
      done;
      s
    end


let extent_to_string extent =
  sprintf "(extent: base = 0x%nx, length = 0x%nx, data = %S)" extent.base extent.length
          (match extent.data with
           | None -> "[]"
           | Some data -> string_from_bigarray data)


let extent_list_to_string extent_list =
  String.concat "" ["["; (String.concat ", " (List.map (fun extent -> extent_to_string extent) extent_list)); "]"]


  

let main =
  if (Array.length Sys.argv) <> 3 then
    failwith "usage: ocaml_test_syscalls spec.idl file_to_read"
  else let footprints = Sys.argv.(1) in
       let filename = Sys.argv.(2) in
       match Syscalls.load_footprints_from_file footprints with
       | None -> failwith "couldn't open footprints"
       | Some env -> begin
           (* shouldn't have to use anything from ctypes once
         actually getting data from the simulator
         as you'll be passing the raw register values
         (as nativeints, if you please) *)
           print_endline "Got footprints." ;
           let filename_bigstring = (string_to_bigarray filename) in begin
               printf "*** %s is the filename; %d is the length of the bigstring\n"
                      filename
                      (Bigarray.Array1.dim filename_bigstring);
               let ptr = raw_address_of_ptr
                           (to_voidp (bigarray_start array1 filename_bigstring)) in begin
                   printf "*** 0x%nx is the address we got\n" ptr;
                   let open_args = [| ptr |] in
                   match do_one_syscall env open_syscall_num open_args with
                   | MoreDataNeeded (_, _) -> assert false
                   | Finished (fd, _) -> begin
                       printf "Got FD retval from open(): %nd\n" fd;
                       match do_one_syscall env read_syscall_num [| fd; 1n; 10n |] with
                       | MoreDataNeeded (_, _) -> assert false
                       | Finished (read_length, write_extents) -> begin
                           printf "*** Read %nd bytes of 10 from fd %nd: %s\n"
                                  read_length fd (extent_list_to_string write_extents);
                           printf "Closing it\n";
                           do_one_syscall env close_syscall_num [| fd |]
                         end
                     end
                 end
             end
         end
                       
