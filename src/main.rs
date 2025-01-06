use process_explorer_2::processes::Process;

fn main() -> Result<(), std::io::Error> {
    // printing all processes
    // let all_processes = unsafe { Process::get_processes_as_map() };
    // let relationships = Process::create_relationships(&all_processes);

    // for process in all_processes.values() {
    //     if !all_processes.contains_key(&process.parent_pid) {
    //         Process::print_process_hierarchy(process.pid, &all_processes, &relationships, 0);
    //     }
    // }

    // getting memory usage for a processes
    // let mut all_processes = Process::get_processes();
    // for process in all_processes.iter_mut() {
    //     println!("{} -> {} {} ", process.parent_pid, process.pid, process.get_process_name());
    //     println!("Memory Usage for {}", process.get_process_name());
    //     if let Some(mem) = unsafe { process.get_memory_usage() } {
    //         println!("{}", mem);
    //     } else {
    //         println!("N/A");
    //     }
    // }

    // getting all loaded dlls in each process
    // for process in Process::get_processes() {
    //     match Process::get_loaded_modules(&process.pid) {
    //         Ok(vector) => {
    //             println!("{:?}", vector);
    //         }
    //         _ => {}
    //     }
    // }

    Ok(())
}
