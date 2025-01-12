use process_explorer_2::processes::Process;
fn main() -> Result<(), std::io::Error> {
    // let mut process_name = "C:\\Windows\\system32\\notepad.exe".to_string();
    // Process::open_process(
    //     &mut process_name,
    //     PROCESS_CREATION_FLAGS::default(),
    // );

    // printing all processes
    let mut all_processes = Process::get_processes_as_map(Process::get_processes());

    for process in all_processes.values_mut() {
        if process.pid != 0 {
            println!(
                "{} {}",
                process.clone().pid,
                process.get_memory_usage().unwrap_or_default()
            );
        }

        // if !all_processes.contains_key(&process.parent_pid) {
        //     Process::print_process_hierarchy(process.pid, &all_processes, &relationships, 0);
        // }
    }

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
