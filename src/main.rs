use sysinfo::SystemExt;
use sysinfo::ProcessExt;
use scanner::pat::{parse, Unit};
 
fn main() {
    let mut system = sysinfo::System::new();
    system.refresh_all();
    let process = sysinfo::SystemExt::get_process_by_name(&system,"game.exe")[0];
    let pid = process.pid();

    println!("{}",pid);
    

    let pattern = parse("84 34 7E 76 ?? ?? ?? ?? 60 34 7E 76").unwrap();
}





//dumps to search for mutual signatures

//ec 2e
// 33 E8 7F 24 DC F8 73 00 DD 7A A8 62 68 F9 73 00 00 F1 76 76 7F 58 8D 52 00 00 00 00 78 F9 73 
// 00 84 34 7E 76 0F E8 7F 24 60 34 7E 76   EC 2E   00 00 00 10 5A 00 00 00 00 00 4C F9 73 00 EC 2E 
// 00 00 BC F9 73 00 00 F1 76 76 BF 59 8D 52 00 00 00 00 CC F9 73 00 12 10 08 01 C8 51 06 00 D0 
// 40 82 76 4F 15 08 01 01 00 00 00 C8 51 06 00 40 59 06 00 E8 F0 B2 53 D7 15 08 01 D7 15 08 01 
// 00 10 5A 00 00 00 00 00 00 00 00 00 00 00 00 00 98 F9 73 00 00 00 00 00 28 FA 73 00 0B 1D 08 
// 01 3C 2F C9 52 00 00 00 00 DC F9 73 00 79 01 8F 77 00 10 5A 00 60 01 8F 77 38 FA 73 00 2D 66 
// A2 77 00 10 5A 00 95 BD 14 25 00 00 00 00 00 00 00 00 00 10 5A 00 00 00 00 00 00 00 00 00 00 
// 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
// E8 F9 73 00 00 00 00 00 40 FA 73 00 D0 86 A3 77 ED D5 CB 52 00 00 00 00 48 FA 73 00 FD 65 A2 
// 77 FF FF FF FF A3 51 A4 77 00 00 00 00 00 00 00 00 D7 15 08 01 00 10 5A

//cf 04

// E3 FF F9 AC D8 FD EF 00 DD 7A DF 67 64 FE EF 00 00 F1 76 76 AB 48 97 DA 00 00 00 00 74 FE EF 
// 00 84 34 7E 76 D7 FF F9 AC 60 34 7E 76   CF   04 00 00 00 C0 D7 00 00 00 00 00 48 FE EF 00 50 00 
// 00 00 B8 FE EF 00 00 F1 76 76 6B 49 97 DA 00 00 00 00 C8 FE EF 00 12 10 08 01 C8 51 13 01 D0 
// 40 82 76 4F 15 08 01 01 00 00 00 C8 51 13 01 C8 CA 13 01 5B FD 33 DB D7 15 08 01 D7 15 08 01 
// 00 C0 D7

//as result 84 34 7E 76 ?? ?? ?? ?? 60 34 7E 76