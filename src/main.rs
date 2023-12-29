use std::{env, u64};
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use nix::sys::{ptrace, wait::waitpid};
use std::process::Command;
use std::os::unix::process::CommandExt;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

#[derive(Debug)]
struct Syscall {
    name: String,
    args: u64,
}

impl Syscall {
    fn new(name: String, args: &str) -> Syscall {
        Syscall {
            name,
            args: args.split(",").count() as u64,
        }
    }
    fn get_name(&self) -> String {
        self.name.clone()
    }
    fn get_args(&self) -> u64{
        self.args
    }

}

fn get_syscalls_table(json_str: &str) -> HashMap<u64, Syscall> {
    let parsed_json = json::parse(json_str).expect("json parse error");
    let mut syscalls_table = HashMap::new();

    let syscalls = parsed_json["x86_64"].members();
    for syscall in syscalls {
        let num = syscall["number"]["int"].as_u64().unwrap();
        let name = syscall["name"].as_str().unwrap();
        let args = syscall["parameters"].as_str().unwrap();
        let syscall = Syscall::new(name.to_string(), args);
        syscalls_table.insert(num, syscall);
    }
    syscalls_table
}



fn main() {
    let args: Vec<String> = env::args().collect();
    let syscalls_path = "syscall.json";
    let mut file_contents = String::new();
    File::open(syscalls_path).expect("file not found")
        .read_to_string(&mut file_contents)
        .expect("something went wrong reading the file"); let syscalls= get_syscalls_table(&file_contents);

    if args.len() < 2 {
        println!("Usage: {} <program>", args[0]);
        return;
    }

    let mut command = Command::new(&args[1]);
    for arg in &args[2..] {
        command.arg(arg);
    }
    unsafe {
        command.pre_exec(|| {
            ptrace::traceme().unwrap();
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    let pid = Pid::from_raw(child.id() as i32);
    let _ = waitpid(pid, None).unwrap();
    println!("pid: {:?}", pid);
    let mut is_have_res = false;
    loop {
        // trace the system call
        ptrace::syscall(pid, None).unwrap();
        let status = waitpid(pid, None).unwrap();
        let regs = ptrace::getregs(pid);
        match status {
            WaitStatus::Exited(_, code) => {
                println!("Process exited with code {:?}", code);
                break;
            }
            WaitStatus::Signaled(p, signal, _) => {
                println!("Process {:?} got signal {:?}.", p, signal);
                break;
            },
            _ => {
                if is_have_res {
                    match regs {
                        Ok(regs) => {
                            let reg_v = vec![regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
                            let a = regs.orig_rax;
                            if let Some(syscall) = syscalls.get(&a){
                                print!("{}(", syscall.get_name());
                                for i in 0..syscall.get_args() {
                                    print!("{:?}", reg_v[i as usize]);
                                    if i != syscall.get_args() - 1 {
                                        print!(", ");
                                    }
                                }
                                println!(") = {:?}", regs.rax);

                            }
                        }
                        Err(_) => {
                            println!("error");
                            break;
                        }
                    }
                }
                is_have_res = !is_have_res;
            }
        }
    }
}

