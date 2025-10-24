# Watchpoint Obfuscation
An experiment to help obfuscate the access/writes of heap memory using shared memory-mapped views  

One of the most common vectors in game cheating (mainly in FPS or RTS where client-sided data is more valuable) is making use of global/static pointers and reading or writing the heap memory which these pointers point to.  
Quite often the act of reading or writing to heap memory goes unchecked by usermode anticheats (KM and hypervisors can of course check this), so they're an easy target for makers of aimbots, wallhacks, etc.  
Because of the available tools, reversing game structures and their static pointers is generally not difficult, even if their values are encrypted/obfuscated. What can we do to make this process more difficult?  

## Typical reversing workflow:  
A typical workflow when reversing software is:  
1) Scan for addresses holding some specific value, such as entity coordinates, hp, or whatever else    
2) Use watchpoints to find out what instructions access/write to the scanned addresses (such as Cheat Engine's 'Find out what writes to this address')  
3) Obtain structure offsets based on the opcodes accessing them (ex. `mov [rbx+70], 5`, the offset is 0x70 and the base of the structure/class is in rbx)
4) Find global/static pointers if they exist by finding references to the struct/class base, or use read watchpoints on the base  

## How this experiment works:  

Memory mapped views map a file or section into memory, and include the option of 'shared memory', which allows multiple views in virtual memory to map to the same physical memory page. When the memory at the physical page is changed, it is automatically updated throughout all the virtual memory views that use the same section handle.  
We can thus use a large number of mapped views which all share the same physical page to make it more difficult to find what instructions read/write to the underlying data structure.  
We try to make the above workflow step 2) more difficult, as watchpoints will not trigger on addresses which are part of shared mapped views.    

1) A section is created via `NtCreateSection`, with the `SEC_NO_CHANGE` flag, disallowing the use of `VirtualProtect` on them. This will be used to make sure views stay as read-only.     
2) `N` number of mapped views are made using the section handle: `N-1` of them are read-only, while only 1 of them is writable. These mapped views cannot have their page protections changed because of the flag mentioned in the above step.  
3) We use the 'placement new' ability in C++ to create our valuable structure at the address of the one writable view.  
4) All views point to the same physical page, so any changes made to memory here are updated throughout all of the views  
5) Any data changes made to structure/class members are done through the one writable view, and reads can be done through any other view  
6) In the end, there are `N` views which have the same memory layout & values of our high-valued struct, and only one of these will trigger watchpoints  
7) When someone tries to scan for any of the values in our high-valued struct, they will get `N` results, where `N-1` of them are unwritable and won't lead back to the instructions which read/write to them (since watchpoints/debug registers won't trigger unless they happened to pick the one writable view). The attacker now needs to spend time going through N addresses, giving ample time to catch them using debug registers  

Also, by default, tools like Cheat Engine ignore mapped memory for scans (this must be turned on manually in the scan settings), so naive attackers will completely skip over our mapped views and fail to reverse our high-valued structures.  

A code example can be found as `AntiWatchpoint.cpp` in this repo, 

## Testing the theory (< 5 minutes commitment)  

You can try things out for yourself by compiling & running the program, and attaching Cheat Engine to it:

1) Try scanning for the value '70' (4-byte integer, not string); this value will increase by 1 every 10 seconds, you can change the sleep time higher if you want    
1.a) If no values are found in heap memory, you may want to make sure the 'writable' box is filled in, meaning 'show writable or non-writable results'  
1.b) If still no values are found in heap memory, you may need to go into CE scan settings and tick the checkbox near the bottom about MEM_MAPPED and then re-try  
2) If you scan quickly before the value increments, you should get atleast 256 results for scanning the value 70. These are our mapped views, and only 1 of them will be writable + able to trigger watchpoints.  
3) The 'real' writable view is selected randomly, so try clicking on a few of the scan result addresses and then right click, and select "Find out what reads/writes to this address"  
4) You'll likely see the value at these addresses increment shortly after, while no results are shown in the watchpoint windows that popped up to track reads/writes.  
4.a) If you got lucky and happened to set a watchpoint on the single writable view, you'll get a result similar to: ".. 89 01 - mov [rcx],eax" -> This should only happen at a 1/256 chance (assuming you didn't modify the number of views in the code)  
5) You can continue to keep setting watchpoints on other view addresses, but this will get tedious very quickly. The next logical step is to hook routines like `MapViewOfFile`, but WINAPI hooks will be easily detectable by any defensive code.  

The console outputs the addresses of each view, along with the writable view, making it easier to find the writable view without going through all 256. In a real scenario, someone would not be given this info, making it difficult to know where the real/writable view is.  

## Downsides
- Once the 'valuable' structure's base pointer + offsets have been reversed, the technique is no longer useful as you will always be pointed to the writable view, given the static pointer. There may be ways to help combat this however, such as avoiding static singletons or global variables.  
- Obviously an increase in virtual memory usage, and any overhead associated with shared memory views (at a minimum, a page must be allocated to house a structure which could potentially be only a few bytes large -> Turning the shared view region into a 'memory arena' which houses multiple structs can help with memory efficiency).  
- Increased complexity, especially when used in game engine code (an LLVM pass might be helpful here, allowing underlying code to be unchanged while the pass implements the shared views)    
- Destructors of structs/classes won't be called when unmapping views at memory which are housing them.  

## Demonstration

<img width="587" height="328" alt="image" src="https://github.com/user-attachments/assets/2056fbf0-edfd-4903-ba33-bccbc6d188d8" />

## Example output

<img width="969" height="266" alt="image" src="https://github.com/user-attachments/assets/d6245585-f3f6-4f4a-9880-1afae3c6d974" />
