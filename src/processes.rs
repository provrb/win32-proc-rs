/// Windows 32 Process Handler
///
/// Use Process to access functions relating to processes
/// such as get all processes, kill processes, etc
use core::fmt;
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    mem,
};

use winapi::{
    ctypes::c_void,
    shared::minwindef::MAX_PATH,
    um::{
        handleapi::CloseHandle,
        tlhelp32::{
            self, CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        },
    },
};

use windows::{
    core::HRESULT,
    Win32::{
        Foundation::{FALSE, HANDLE, HMODULE, TRUE},
        System::{
            ProcessStatus::{
                EnumProcessModules, GetModuleBaseNameA, GetProcessMemoryInfo,
                PROCESS_MEMORY_COUNTERS,
            },
            Threading::{
                OpenProcess, TerminateProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION,
                PROCESS_VM_READ,
            },
        },
    },
};

// process identifiers are u32
type Pid = u32;

// conversion factors
const BYTES_PER_KB: u32 = 1024;
const BYTES_PER_GB: u64 = 1024 * 1024 * 1024; // 1,073,741,824 bytes per gb. convert from b to gb
const BYTES_PER_MB: u64 = 1024 * 1024;

#[derive(Default, Clone, PartialEq)]
pub(crate) struct MemoryInner {
    pub working_set_size: usize,    // current memory usage for process
    pub peak_set_size: usize,       // peak memory usage for process,
    pub page_file_size: usize,      // virtual memory allocated for process
    pub peak_page_file_size: usize, // peak virtual memory used backed by page file
}

#[derive(Default, Clone, PartialEq)]
pub struct Memory {
    inner: MemoryInner,
}

#[derive(Clone, PartialEq)]
pub struct Process {
    pub pid: Pid,                  // process id
    pub child_threads: Pid,        // number of child threads started by the process
    pub parent_pid: Pid,           // process id of this processes parent
    pub exe_path: [u16; MAX_PATH], // path of the exe of the process
    pub thread_base_priority: i32, // base priority of any child threads
    pub process_memory: Memory,    // memory usage for a process
}

impl MemoryInner {
    // construct a MemoryInner description
    // from win32 api 'PROCESS_MEMORY_COUNTERS' struct
    pub fn from_memory_counters(mem_info: &PROCESS_MEMORY_COUNTERS) -> Self {
        Self {
            working_set_size: mem_info.WorkingSetSize,
            peak_set_size: mem_info.PeakWorkingSetSize,
            page_file_size: mem_info.PagefileUsage,
            peak_page_file_size: mem_info.PeakPagefileUsage,
        }
    }
}

// Print out all details about a memory object
impl fmt::Display for Memory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Memory Usage:        {} MB\n\
            Peak Memory Usage:   {} MB\n\
            Page File Size:      {} MB\n\
            Peak Page File Size: {} MB\n",
            self.current_mem_usage_mb(),
            self.max_mem_usage_mb(),
            self.page_file_usage_mb(),
            self.max_page_file_usage_mb(),
        )
    }
}

// Default values for process
impl Default for Process {
    fn default() -> Self {
        Self {
            pid: 0,
            child_threads: 0,
            parent_pid: 0,
            exe_path: [0; MAX_PATH],
            thread_base_priority: 0,
            process_memory: Memory::new(),
        }
    }
}

// Print out all values of a process aligned
impl fmt::Display for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Process ID:             {}\n\
             Process Name:           {}\n\
             # of Child Threads:     {}\n\
             Parent Process ID:      {}\n\
             Thread Base Priority:   {}",
            self.pid,
            self.get_process_name(),
            self.child_threads,
            self.parent_pid,
            self.thread_base_priority
        )
    }
}

/// Implementation of the `HandleManager` trait for `HANDLE`.
pub(crate) trait HandleManager<T> {
    fn cleanup(handle: T);
    fn from_process_id(pid: &Pid, access: PROCESS_ACCESS_RIGHTS) -> Option<T>;
    fn as_mut_c_void(handle: T) -> *mut c_void;
}

impl HandleManager<HANDLE> for HANDLE {
    /// Cleans up the given handle by closing it.
    ///
    /// # Parameters
    /// - `handle`: The handle to be closed.
    ///
    /// # Safety
    /// This function is unsafe because it calls the `CloseHandle` function, which can potentially
    /// close an invalid handle if not used correctly.
    fn cleanup(handle: HANDLE) {
        unsafe {
            CloseHandle(Self::as_mut_c_void(handle));
        }
    }

    /// Creates a handle from a process ID with the specified access rights.
    ///
    /// # Parameters
    /// - `pid`: The process ID for which to create the handle.
    /// - `access`: The access rights for the handle.
    ///
    /// # Returns
    /// An `Option<HANDLE>` containing the handle if successful, or `None` if the handle could not be created.
    ///
    /// # Safety
    /// This function is unsafe because it calls the `OpenProcess` function, which can potentially
    /// open a handle to a process with insufficient or incorrect access rights.
    fn from_process_id(pid: &Pid, access: PROCESS_ACCESS_RIGHTS) -> Option<HANDLE> {
        let res = unsafe { OpenProcess(access, false, *pid) };

        if res.is_err() {
            return None;
        }

        let handle = res.unwrap();
        Some(handle)
    }

    /// Converts a handle to a mutable pointer to `c_void`.
    ///
    /// # Parameters
    /// - `handle`: The handle to be converted.
    ///
    /// # Returns
    /// A mutable pointer to `c_void` representing the handle.
    fn as_mut_c_void(handle: HANDLE) -> *mut c_void {
        handle.0 as *mut c_void
    }
}

/// Represents memory usage information for a process.
impl Memory {
    /// Creates a new instance of `Memory` with default values.
    ///
    /// # Returns
    /// A new `Memory` instance with all memory values set to their default state.
    pub fn new() -> Self {
        Self {
            inner: MemoryInner::default(),
        }
    }

    /// Creates a new instance of `Memory` initialized with data from `PROCESS_MEMORY_COUNTERS`.
    ///
    /// # Parameters
    /// - `counters`: A reference to a `PROCESS_MEMORY_COUNTERS` struct containing memory information.
    ///
    /// # Returns
    /// A new `Memory` instance populated with memory usage data from the provided `PROCESS_MEMORY_COUNTERS`.
    pub fn new_from_counters(counters: &PROCESS_MEMORY_COUNTERS) -> Self {
        Self {
            inner: MemoryInner::from_memory_counters(counters),
        }
    }

    /// Retrieves the current memory usage in megabytes.
    ///
    /// # Returns
    /// The current working set size, representing the amount of memory currently being used, in megabytes.
    pub fn current_mem_usage_mb(&self) -> u64 {
        self.inner.working_set_size as u64 / BYTES_PER_MB
    }

    /// Retrieves the current page file usage in megabytes.
    ///
    /// # Returns
    /// The amount of memory being used in the page file, in megabytes.
    pub fn page_file_usage_mb(&self) -> u64 {
        self.inner.page_file_size as u64 / BYTES_PER_MB
    }

    /// Retrieves the maximum memory usage recorded in megabytes.
    ///
    /// # Returns
    /// The peak working set size, representing the maximum amount of memory used, in megabytes.
    pub fn max_mem_usage_mb(&self) -> u64 {
        self.inner.peak_set_size as u64 / BYTES_PER_MB
    }

    /// Retrieves the maximum page file usage recorded in megabytes.
    ///
    /// # Returns
    /// The peak amount of memory used in the page file, in megabytes.
    pub fn max_page_file_usage_mb(&self) -> u64 {
        self.inner.peak_page_file_size as u64 / BYTES_PER_MB
    }
}

impl Process {
    /// Creates a new instance of `Process`.
    ///
    /// # Parameters
    /// - `pid`: The process ID.
    /// - `child_threads`: The number of child threads associated with the process.
    /// - `parent_pid`: The parent process ID.
    /// - `exe_path`: The path to the executable file associated with the process.
    /// - `thread_base_priority`: The base priority of the threads in the process.
    /// - `process_memory`: The memory information for the process.
    ///
    /// # Returns
    /// A new `Process` instance.
    pub fn new(
        pid: u32,
        child_threads: u32,
        parent_pid: u32,
        exe_path: [u16; MAX_PATH],
        thread_base_priority: i32,
        process_memory: Memory,
    ) -> Self {
        Self {
            pid,
            child_threads,
            parent_pid,
            exe_path,
            thread_base_priority,
            process_memory,
        }
    }

    /// Retrieves the memory usage information of the process.
    ///
    /// # Returns
    /// An `Option<Memory>` containing the memory usage details of the process. Returns `None` if memory usage couldn't be retrieved.
    pub fn get_memory_usage(&mut self) -> Option<Memory> {
        let handle =
            HANDLE::from_process_id(&self.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
        let mut mem_info = PROCESS_MEMORY_COUNTERS::default();

        let result = unsafe {
            GetProcessMemoryInfo(
                handle,
                &mut mem_info as *mut PROCESS_MEMORY_COUNTERS,
                size_of_val::<PROCESS_MEMORY_COUNTERS>(&mem_info) as u32,
            )
        };

        HANDLE::cleanup(handle);

        if result.is_err() {
            return None;
        }

        Some(Memory::new_from_counters(&mem_info))
    }

    /// Converts a `PROCESSENTRY32W` structure to a `Process` instance.
    ///
    /// # Parameters
    /// - `process_entry`: A reference to a `PROCESSENTRY32W` structure representing a process entry.
    ///
    /// # Returns
    /// A `Process` instance populated with data from the `PROCESSENTRY32W`.
    pub fn from_process_entry(process_entry: &PROCESSENTRY32W) -> Self {
        Self::new(
            process_entry.th32ProcessID,
            process_entry.cntThreads,
            process_entry.th32ParentProcessID,
            process_entry.szExeFile,
            process_entry.pcPriClassBase,
            Memory::new(),
        )
    }

    /// Get a Process struct from a process ID
    ///
    /// # Parameters
    /// - 'pid': The pid of the process to search for
    ///
    /// # Returns
    /// A 'Process' instance describing the process with 'pid'
    pub fn from_pid(pid: &Pid) -> Process {
        if let Some(proc) = Self::get_processes_as_map(Self::get_processes()).get(pid) {
            return proc.clone();
        }

        Process::default()
    }

    /// Get all processes with 'name'
    ///
    /// # Parameters
    /// - 'name': The name of the processes to retrieve
    ///
    /// # Returns
    /// A vector of Process structs describing all processes found with 'name'
    pub fn from_proc_name(name: &str) -> Vec<Process> {
        let all_processes = Self::get_processes();
        let mut processes: Vec<Process> = Vec::new();

        for process in all_processes {
            if process.get_process_name() == name {
                processes.push(process);
            }
        }

        processes
    }

    /// Retrieves the process name from the `exe_path`, removing null terminators.
    ///
    /// # Returns
    /// The process name as a `String`, excluding any null terminators.
    pub fn get_process_name(&self) -> String {
        String::from_utf16_lossy(&self.exe_path)
            .trim_end_matches('\0')
            .to_string()
    }

    /// Converts a vector of `Process` instances to a `HashMap` of `PID` to `Process`.
    ///
    /// # Parameters
    /// - `processes`: A vector of `Process` instances.
    ///
    /// # Returns
    /// A `HashMap` where the key is a process ID (`PID`), and the value is the corresponding `Process`.
    pub fn get_processes_as_map(processes: Vec<Process>) -> HashMap<Pid, Process> {
        let mut map: HashMap<Pid, Process> = HashMap::new();

        for process in processes {
            map.insert(process.pid, process);
        }

        map
    }

    /// Prints the hierarchy of processes starting from the specified `pid`, displaying parent-child relationships.
    ///
    /// # Parameters
    /// - `pid`: The process ID of the root process to start the hierarchy from.
    /// - `all_processes`: A reference to a `HashMap` of all processes.
    /// - `parent_to_children`: A reference to a `HashMap` that maps parent PIDs to child PIDs.
    /// - `indent`: The number of spaces to indent each level of the hierarchy.
    pub fn print_process_hierarchy(
        pid: Pid,
        all_processes: &HashMap<Pid, Process>,
        parent_to_children: &HashMap<Pid, Vec<Pid>>,
        indent: usize,
    ) {
        if let Some(process) = all_processes.get(&pid) {
            println!("{}{}", " ".repeat(indent), process.get_process_name());
            if let Some(children) = parent_to_children.get(&pid) {
                for &child_pid in children {
                    Self::print_process_hierarchy(
                        child_pid,
                        all_processes,
                        parent_to_children,
                        indent + 4,
                    );
                }
            }
        }
    }

    /// Retrieves a list of all running processes.
    ///
    /// # Returns
    /// A vector of `Process` instances representing all currently running processes.
    pub fn get_processes() -> Vec<Process> {
        // take a snapshot of all current processes
        let snapshot: HANDLE =
            unsafe { HANDLE(CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPPROCESS, 0) as isize) };

        if snapshot.is_invalid() {
            return Vec::new();
        }

        let mut process_entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        // process first entry, add it to process list
        if unsafe {
            Process32FirstW(
                HANDLE::as_mut_c_void(snapshot),
                &mut process_entry as *mut PROCESSENTRY32W,
            )
        } == FALSE.0
        {
            HANDLE::cleanup(snapshot);
            return Vec::new();
        }

        // the processes were looking for
        // depending on start, would be either all processes or children processes of parent ppid
        let mut processes: Vec<Process> = Vec::new();

        processes.push(Process::from_process_entry(&process_entry));

        // iterate through all processes
        while unsafe {
            Process32NextW(
                HANDLE::as_mut_c_void(snapshot),
                &mut process_entry as *mut PROCESSENTRY32W,
            )
        } == TRUE.0
        {
            processes.push(Process::from_process_entry(&process_entry));
        }

        HANDLE::cleanup(snapshot);

        processes
    }

    /// Creates a mapping of parent PIDs to their respective child PIDs.
    ///
    /// # Parameters
    /// - `process_list`: A reference to a `HashMap` containing all processes.
    ///
    /// # Returns
    /// A `HashMap` that maps parent PIDs to a vector of child PIDs.
    pub fn create_relationships(process_list: &HashMap<Pid, Process>) -> HashMap<Pid, Vec<Pid>> {
        // parent pid : { children pid's }
        let mut parent_to_children: HashMap<Pid, Vec<Pid>> = HashMap::new();

        for process in process_list.values() {
            parent_to_children
                .entry(process.parent_pid)
                .or_default()
                .push(process.pid);
        }

        parent_to_children
    }

    /// Retrieves all top-level processes (i.e., processes that do not have a parent).
    ///
    /// # Returns
    /// A vector of `Process` instances representing top-level processes.
    pub fn get_top_level_processes() -> Vec<Process> {
        let mut top_level_processes: Vec<Process> = Vec::new();
        let all_processes = Self::get_processes();
        let process_map: HashMap<Pid, Process> = Self::get_processes_as_map(all_processes.clone());

        for process in all_processes.iter() {
            if !process_map.contains_key(&process.parent_pid) {
                top_level_processes.push(process.clone());
            }
        }

        top_level_processes
    }

    /// Terminates the specified process by its process ID (PID).
    ///
    /// # Arguments
    /// - `pid` The process ID (PID) of the process to terminate.
    ///
    /// # Returns
    /// Ok(()) if the process was successfully terminated.
    /// Err(std::io::Error)` if an error occurred while opening or terminating the process.
    pub fn kill_process(pid: &Pid) -> Result<(), std::io::Error> {
        let process = HANDLE::from_process_id(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);

        if process.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                "Failed to get HANDLE from process ID",
            ));
        }

        let handle = process.unwrap();

        unsafe {
            let term = TerminateProcess(handle, 0);
            HANDLE::cleanup(handle);

            if term.is_err() {
                return Err(std::io::Error::new(
                    ErrorKind::Other,
                    "Failed to terminate process",
                ));
            }
        }

        Ok(())
    }

    /// Retrieves a list of all loaded modules (DLLs) for the specified process.
    ///
    /// # Arguments
    /// - `pid` The process ID (PID) of the process whose loaded modules are to be retrieved.
    ///
    /// # Returns
    /// A `Result` containing:
    /// - `Ok(Vec<String>)` A vector of strings representing the names of all loaded DLLs.
    /// - `Err(windows::core::Error)` An error if the process could not be opened or modules could not be enumerated.
    pub fn get_loaded_modules(pid: &Pid) -> Result<Vec<String>, windows::core::Error> {
        let opt = HANDLE::from_process_id(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        let mut modules: Vec<HMODULE> = vec![HMODULE::default(); 1024];
        let mut needed: u32 = 0;
        let handle = opt.unwrap_or_default();

        if handle.is_invalid() {
            return Err(windows::core::Error::new(
                HRESULT::default(),
                "Error getting handle from process id",
            ));
        }

        let success = unsafe {
            EnumProcessModules(
                handle,
                modules.as_mut_ptr(),
                (modules.len() * size_of::<HMODULE>()) as u32,
                &mut needed,
            )
        };

        if success.is_err() {
            HANDLE::cleanup(handle);
            return Err(windows::core::Error::new(
                HRESULT::default(),
                "Failed to enumerate process modules",
            ));
        }

        // calculate space needed for all modules
        // get count of HMODULES by dividing needed
        let module_count = needed as usize / size_of::<HMODULE>();
        modules.resize(module_count, HMODULE::default());

        let mut module_names = Vec::new();

        // get all loaded dlls/modules
        for module in &modules[1..] {
            let mut name_buffer = vec![0u8; MAX_PATH];
            unsafe { GetModuleBaseNameA(handle, *module, &mut name_buffer) };

            if let Ok(name) = String::from_utf8(name_buffer) {
                module_names.push(name.trim_end_matches('\0').to_string());
            }
        }

        HANDLE::cleanup(handle);

        Ok(module_names)
    }

    
}
