### LoadLibrary Ex

A simple program that calls LoadLibrary and/or FreeLibrary in a remote 64 bit process by injecting shellcode and creating a
remote thread. The program takes a parameter for the process name, the dll file path, and an optional parameter to only
call FreeLibrary on the dll (make sure to use the parameters in order). It can also be used with the CLion build system
to help debug dlls in processes that wouldn't normally load them.

**Command Line Usage**

```shell
loadlibrary-ex.exe [-free] -exe.exe -dll.dll
```

**CLion Run/Debug Configuration Usage**

1. Keep the **Target** set to the dll.
2. Set the **Executable** to the loadlibrary-ex.exe path.
3. Set the **Program Arguments** to "-exe.exe -$CMakeCurrentBuildDir$\$CMakeCurrentTargetName$.dll", replace the
   parameters with your target executable name and dll name if needed.
4. Under **Before Launch** add a **Run External Tool**.
5. Set the **Program** to the loadlibrary-ex.exe path and **Arguments** to "-free -exe.exe
   -$CMakeCurrentBuildDir$\$CMakeCurrentTargetName$.dll".
6. Each time you want to debug the process, attach to it with LLDB, then run the configuration, and all your breakpoints
   will be hit!
7. Unfortunately, you will have to reattach LLDB each time you want to rebuild even if the dll is unloaded because LLDB
   keeps handles open to the dll file.
